"""
Enhanced hot reload implementation with zero-downtime reloads
and state preservation capabilities.
"""

import asyncio
import logging
import sys
import importlib
import inspect
from pathlib import Path
from typing import Set, Dict, Any, Callable, Optional, List
from functools import partial
import weakref
import ast
from watchfiles import awatch

class ReloadStateManager:
    """
    Manages state preservation across reloads.
    Uses weak references to avoid memory leaks.
    """
    _preserved_state: Dict[str, Any] = {}
    _weak_refs: Dict[str, weakref.ref] = {}

    @classmethod
    def preserve(cls, key: str, value: Any) -> None:
        """
        Preserve a value across reloads.
        """
        if inspect.iscoroutine(value):
            raise ValueError("Cannot preserve coroutine objects")
        
        if inspect.isfunction(value) or inspect.isclass(value):
            # For functions and classes, store their qualified name
            cls._preserved_state[key] = f"{value.__module__}.{value.__qualname__}"
        else:
            # For other objects, store the actual value
            cls._preserved_state[key] = value
            # Keep a weak reference to track object lifecycle
            cls._weak_refs[key] = weakref.ref(value)
    
    @classmethod
    def restore(cls, key: str) -> Optional[Any]:
        """
        Restore a preserved value.
        """
        if key not in cls._preserved_state:
            return None
            
        value = cls._preserved_state[key]
        
        if isinstance(value, str) and "." in value:
            # Handle restored functions and classes
            try:
                module_name, qualname = value.rsplit(".", 1)
                module = importlib.import_module(module_name)
                return getattr(module, qualname)
            except (ImportError, AttributeError):
                return None
        
        # For other objects, check if they're still alive
        if key in cls._weak_refs:
            obj = cls._weak_refs[key]()
            if obj is not None:
                return obj
            
            # Object was garbage collected, remove it
            del cls._preserved_state[key]
            del cls._weak_refs[key]
            
        return value
    
    @classmethod
    def clear(cls) -> None:
        """
        Clear all preserved state.
        """
        cls._preserved_state.clear()
        cls._weak_refs.clear()

class ModuleAnalyzer:
    """
    Analyzes Python modules to determine reload safety and dependencies.
    """
    
    @staticmethod
    def is_safe_to_reload(module_path: Path) -> bool:
        """
        Determine if a module is safe to reload without full server restart.
        """
        try:
            with open(module_path) as f:
                tree = ast.parse(f.read())
            
            # Check for patterns that would make reloading unsafe
            for node in ast.walk(tree):
                # Check for module-level state
                if isinstance(node, ast.Assign) and any(
                    isinstance(target, ast.Name) for target in node.targets
                ):
                    return False
                
                # Check for decorators that might cache or modify function behavior
                if isinstance(node, ast.FunctionDef) and node.decorator_list:
                    return False
                
                # Check for metaclasses
                if isinstance(node, ast.ClassDef) and node.keywords:
                    for keyword in node.keywords:
                        if keyword.arg == "metaclass":
                            return False
            
            return True
        except Exception:
            # If we can't analyze the file, err on the side of caution
            return False
    
    @staticmethod
    def get_module_dependencies(module_path: Path) -> Set[Path]:
        """
        Get all direct dependencies of a module.
        """
        dependencies = set()
        try:
            with open(module_path) as f:
                tree = ast.parse(f.read())
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for name in node.names:
                        dependencies.add(name.name.split(".")[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        dependencies.add(node.module.split(".")[0])
            
            # Convert module names to paths
            return {
                Path(sys.modules[dep].__file__)
                for dep in dependencies
                if dep in sys.modules
            }
        except Exception:
            return set()

class HotReloader:
    """
    Enhanced hot reload implementation with zero-downtime capability
    and state preservation.
    """
    
    def __init__(
        self,
        reload_dirs: List[str],
        on_reload: Callable[[Set[str]], None],
        state_manager: Optional[ReloadStateManager] = None
    ):
        self.reload_dirs = [Path(d).resolve() for d in reload_dirs]
        self.on_reload = on_reload
        self.state_manager = state_manager or ReloadStateManager()
        self.module_analyzer = ModuleAnalyzer()
        self._watch_task: Optional[asyncio.Task] = None
        self._running = False
        self.logger = logging.getLogger("ruvicorn.hot_reload")
    
    async def start(self) -> None:
        """
        Start watching for file changes.
        """
        if self._running:
            return
            
        self._running = True
        self._watch_task = asyncio.create_task(self._watch_for_changes())
        self.logger.info(f"Hot reload watching directories: {self.reload_dirs}")
    
    async def stop(self) -> None:
        """
        Stop watching for file changes.
        """
        self._running = False
        if self._watch_task:
            self._watch_task.cancel()
            try:
                await self._watch_task
            except asyncio.CancelledError:
                pass
            self._watch_task = None
    
    async def _watch_for_changes(self) -> None:
        """
        Watch for file changes and handle reloads.
        """
        watch_dirs = [str(d) for d in self.reload_dirs]
        
        async for changes in awatch(*watch_dirs):
            if not self._running:
                break
                
            changed_files = {Path(change[1]).resolve() for change in changes}
            python_changes = {
                f for f in changed_files
                if f.suffix in {".py", ".pyd", ".so"}
            }
            
            if not python_changes:
                continue
                
            # Group changes by their reload requirements
            safe_reloads = set()
            unsafe_reloads = set()
            
            for changed_file in python_changes:
                if self.module_analyzer.is_safe_to_reload(changed_file):
                    safe_reloads.add(changed_file)
                    # Add dependencies that also need reloading
                    deps = self.module_analyzer.get_module_dependencies(changed_file)
                    for dep in deps:
                        if self.module_analyzer.is_safe_to_reload(dep):
                            safe_reloads.add(dep)
                        else:
                            unsafe_reloads.add(dep)
                else:
                    unsafe_reloads.add(changed_file)
            
            # Handle the reloads
            if unsafe_reloads:
                # If any changes require unsafe reload, do a full reload
                self.logger.info(
                    f"Changes requiring full reload: {unsafe_reloads}"
                )
                await self.on_reload(python_changes)
            elif safe_reloads:
                # Otherwise, do selective reloading
                self.logger.info(
                    f"Changes safe for hot reload: {safe_reloads}"
                )
                await self._handle_safe_reloads(safe_reloads)
    
    async def _handle_safe_reloads(self, files_to_reload: Set[Path]) -> None:
        """
        Handle reloading of files that are safe to reload without
        full server restart.
        """
        for file_path in files_to_reload:
            module_name = self._get_module_name(file_path)
            if module_name in sys.modules:
                try:
                    # Reload the module
                    module = sys.modules[module_name]
                    importlib.reload(module)
                    self.logger.info(f"Hot reloaded module: {module_name}")
                except Exception as e:
                    self.logger.error(
                        f"Error hot reloading {module_name}: {str(e)}"
                    )
                    # If hot reload fails, fall back to full reload
                    await self.on_reload({str(file_path)})
                    return
    
    def _get_module_name(self, file_path: Path) -> str:
        """
        Convert a file path to a module name.
        """
        for reload_dir in self.reload_dirs:
            try:
                relative = file_path.relative_to(reload_dir)
                return str(relative.with_suffix("")).replace("/", ".")
            except ValueError:
                continue
        return file_path.stem
    
    def preserve_state(self, key: str, value: Any) -> None:
        """
        Preserve a value across reloads.
        """
        self.state_manager.preserve(key, value)
    
    def restore_state(self, key: str) -> Optional[Any]:
        """
        Restore a preserved value.
        """
        return self.state_manager.restore(key)
    
    def clear_preserved_state(self) -> None:
        """
        Clear all preserved state.
        """
        self.state_manager.clear()

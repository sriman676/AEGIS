## 2024-05-15 - Async I/O blocking main thread in FastAPI
**Learning:** Found synchronous `subprocess.run` and `os.path.exists` calls inside an `async def` FastAPI route (`/repo/intake`), which completely blocks the asyncio event loop during execution, degrading concurrent request performance.
**Action:** Always use `asyncio.create_subprocess_exec` for subprocesses and offload synchronous file I/O to thread pools (`asyncio.to_thread`) inside async routes.

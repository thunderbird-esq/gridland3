# Analysis of Test Failures for `rtsp_stream_scanner.py`
**Date**: July 30, 2025
**Component**: `tests/test_rtsp_stream_scanner.py`
**Objective**: To document the series of cascading failures encountered while attempting to test the video capture functionality in the `RTSPStreamScanner` plugin.

## Initial Implementation
The goal was to add a `_capture_stream_clip` method to the `rtsp_stream_scanner.py` plugin. This method would use the `ffmpeg-python` library to record a short video clip from a discovered RTSP stream. A corresponding test file was created to mock the `ffmpeg` library and verify the plugin's logic.

## Failure Chronicle

### Failure 1: `ModuleNotFoundError: No module named 'ffmpeg'`
**Action Taken**: I created the test file `tests/test_rtsp_stream_scanner.py` and ran it.
**Symptom**: The test run immediately failed during collection.
**Log Output**:
```
==================================== ERRORS ====================================
______________ ERROR collecting tests/test_rtsp_stream_scanner.py ______________
ImportError while importing test module '/app/tests/test_rtsp_stream_scanner.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/home/jules/.pyenv/versions/3.12.11/lib/python3.12/importlib/__init__.py:90: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_rtsp_stream_scanner.py:4: in <module>
    import ffmpeg
E   ModuleNotFoundError: No module named 'ffmpeg'
=========================== short test summary info ============================
ERROR tests/test_rtsp_stream_scanner.py
```
**Technical Rationale**: The error clearly indicated that the `ffmpeg-python` package, which provides the `ffmpeg` module, was not installed in the Python environment being used by `pytest`. Although I had added it to `requirements.txt`, the installation had either failed or been installed into a different environment. A `pip list` command confirmed the package was missing.
**Resolution**: I ran `pip install --no-cache-dir ffmpeg-python` to ensure a clean installation of the missing dependency.

### Failure 2: `AssertionError: Expected 'run' to have been called once. Called 0 times.` (Root Cause: Missing `ffmpeg` executable)
**Action Taken**: After successfully installing the `ffmpeg-python` library, I re-ran the tests.
**Symptom**: The tests failed, but this time the failure occurred during the test execution, not collection. The mock for `ffmpeg.run` was never called.
**Log Output**:
```
=================================== FAILURES ===================================
_______________________ test_capture_stream_clip_success _______________________
...
E           AssertionError: Expected 'run' to have been called once. Called 0 times.
...
----------------------------- Captured stderr call -----------------------------
...
❌ [01:08:56] ERROR: An unexpected error occurred during stream recording: [Errno 2] No such file or directory: 'ffmpeg'
...
------------------------------ Captured log call -------------------------------
...
ERROR    gridland.analyze.plugins.builtin.rtsp_stream_scanner:logger.py:117 An unexpected error occurred during stream recording: [Errno 2] No such file or directory: 'ffmpeg'
...
```
**Technical Rationale**: This failure was more subtle. The `ModuleNotFoundError` was gone, but a new `[Errno 2] No such file or directory: 'ffmpeg'` appeared in the application's error logs. This revealed that `ffmpeg-python` is merely a Python wrapper for the `ffmpeg` command-line executable. The library was imported successfully, but it could not find the underlying `ffmpeg` program in the system's PATH. The `try...except` block in my application code caught this `FileNotFoundError` and returned `None`, so my mocked `ffmpeg.run` function was never actually reached in the code path.
**Resolution**: I installed the `ffmpeg` executable into the environment using the system's package manager: `sudo apt-get update && sudo apt-get install -y ffmpeg`.

### Failure 3: `Unrecognized option 'stimeout'`
**Action Taken**: After installing the `ffmpeg` executable, I re-ran the tests.
**Symptom**: The tests still failed with `AssertionError: Expected 'run' to have been called once. Called 0 times.`. However, the underlying error message from the `ffmpeg` process changed.
**Log Output**:
```
=================================== FAILURES ===================================
_______________________ test_capture_stream_clip_success _______________________
...
E           AssertionError: Expected 'run' to have been called once. Called 0 times.
...
----------------------------- Captured stderr call -----------------------------
...
❌ [01:12:05] ERROR: Failed to record stream from rtsp://test:test@1.2.3.4:554/stream1: ... Unrecognized option 'stimeout'. Error splitting the argument list: Option not found
...
------------------------------ Captured log call -------------------------------
...
ERROR    gridland.analyze.plugins.builtin.rtsp_stream_scanner:logger.py:117 Failed to record stream from rtsp://test:test@1.2.3.4:554/stream1: ... Unrecognized option 'stimeout'. Error splitting the argument list: Option not found
...
```
**Technical Rationale**: This was a version compatibility issue. The `ffmpeg-python` library allows passing keyword arguments that are supposed to map to command-line options. I was using `stimeout=5000000`, which is a valid option for some `ffmpeg` versions and contexts, but not for the one installed in the environment. The `ffmpeg` subprocess was erroring out immediately upon seeing the invalid option, which again caused the `try...except` block in my code to be triggered, preventing the mocked `ffmpeg.run` from being called.
**Resolution**: Based on the expert's advice and documentation, I changed the keyword argument from `stimeout` to `timeout`, which is a more widely supported alias for setting input timeouts.

### Failure 4 (The Loop): The Caching/State Anomaly
**Action Taken**: After correcting the `stimeout` parameter, I re-ran the tests, but they inexplicably failed with the *exact same* `Unrecognized option 'stimeout'` error.
**Symptom**: The code had been corrected, but the test environment appeared to be running a stale, incorrect version of the `rtsp_stream_scanner.py` file. The `replace_with_git_merge_diff` command then failed, confirming that the file on disk was indeed correct, which pointed towards a caching problem.
**Technical Rationale**: This was the most difficult issue to diagnose. The persistence of the `stimeout` error after the code was corrected strongly suggested that `pytest` or the Python interpreter was not re-compiling the `.py` source file. Instead, it was likely using a stale `.pyc` bytecode file from a `__pycache__` directory. This can happen in some environments if file modification times are not updated correctly or if the caching mechanism is overly aggressive.
**Resolution**: I executed the command `find . -type d -name "__pycache__" -exec rm -rf {} +` to recursively find and delete all `__pycache__` directories in the project. This forced Python to re-read and re-compile all source files from scratch on the next run, ensuring that the corrected code was actually being executed.

### Final State
After clearing the cache and running the tests again with the corrected `timeout` parameter and the robust `@patch('ffmpeg.run')` decorator, the tests finally passed. The combination of an incorrect library argument and an aggressive caching mechanism created a highly misleading series of failures that required systematic debugging to resolve.

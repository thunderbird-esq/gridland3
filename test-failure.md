Last login: Wed Jul 30 05:31:28 on ttys000
 michaelraftery@michaels-MacBook-Pro  ~  git clone https://github.com/thunderbird-esq/gridland3/tree/feature/advanced-fingerprinting-1\
> 
Cloning into 'advanced-fingerprinting-1'...
fatal: repository 'https://github.com/thunderbird-esq/gridland3/tree/feature/advanced-fingerprinting-1/' not found
 ✘ michaelraftery@michaels-MacBook-Pro  ~  git clone --branch feature-advanced-fingerprinting-1 https://github.com/thunderbird-esq/gridland3.git
Cloning into 'gridland3'...
fatal: Remote branch feature-advanced-fingerprinting-1 not found in upstream origin
 ✘ michaelraftery@michaels-MacBook-Pro  ~  cd HB-v2-gemmy-072525
 michaelraftery@michaels-MacBook-Pro  ~/HB-v2-gemmy-072525   main ±  git clone --branch feature-advanced-fingerprinting-1 https://github.com/thunderbird-esq/gridland3.git
Cloning into 'gridland3'...
fatal: Remote branch feature-advanced-fingerprinting-1 not found in upstream origin
 ✘ michaelraftery@michaels-MacBook-Pro  ~/HB-v2-gemmy-072525   main ±  git remote          
main
 michaelraftery@michaels-MacBook-Pro  ~/HB-v2-gemmy-072525   main ±  git remote -v
main	https://github.com/thunderbird-esq/gridland3.git (fetch)
main	https://github.com/thunderbird-esq/gridland3.git (push)
 michaelraftery@michaels-MacBook-Pro  ~/HB-v2-gemmy-072525   main ±  cd                   
 michaelraftery@michaels-MacBook-Pro  ~  git clone --branch feature/advanced-fingerprinting-1 https://github.com/thunderbird-esq/gridland3.git
Cloning into 'gridland3'...
remote: Enumerating objects: 465, done.
remote: Counting objects: 100% (465/465), done.
remote: Compressing objects: 100% (332/332), done.
remote: Total 465 (delta 241), reused 333 (delta 124), pack-reused 0 (from 0)
Receiving objects: 100% (465/465), 587.81 KiB | 7.35 MiB/s, done.
Resolving deltas: 100% (241/241), done.
 michaelraftery@michaels-MacBook-Pro  ~  cd gridland3         
 michaelraftery@michaels-MacBook-Pro  ~/gridland3   feature/advanced-fingerprinting-1  ls
AGENTS.md                LICENSE                  NECESSARY-WORK-8.md      config.yaml
ALARMCLOCK.md            NECESSARY-WORK-1.md      NECESSARY-WORK-9.md      discovery_results.json
ALARMCLOCK130AM072625.md NECESSARY-WORK-10.md     NECESSARY-WORK.md        pytest.ini
CLAUDE.md                NECESSARY-WORK-2.md      NEXT-TESTS.md            requirements.txt
CamXploit.ipynb          NECESSARY-WORK-3.md      README.md                setup.py
CamXploit.py             NECESSARY-WORK-4.md      ROADMAP.md               src
DEVLOG.md                NECESSARY-WORK-5.md      TESTING-PROGRESS.md      tests
GEMINI.md                NECESSARY-WORK-6.md      TEST_PHASE3.md           validate_gridland.py
INTEGRATION_CHECKLIST.md NECESSARY-WORK-7.md      analysis_results.json
 michaelraftery@michaels-MacBook-Pro  ~/gridland3   feature/advanced-fingerprinting-1  python3 -m venv venv 
 michaelraftery@michaels-MacBook-Pro  ~/gridland3   feature/advanced-fingerprinting-1  source venv/bin/activate
(venv)  michaelraftery@michaels-MacBook-Pro  ~/gridland3   feature/advanced-fingerprinting-1  pip install -r requirements.txt
pip install -e .
Collecting requests>=2.31.0
  Using cached requests-2.32.4-py3-none-any.whl (64 kB)
Collecting click>=8.1.0
  Using cached click-8.2.1-py3-none-any.whl (102 kB)
Collecting colorama>=0.4.6
  Using cached colorama-0.4.6-py2.py3-none-any.whl (25 kB)
Collecting scikit-learn>=1.0
  Downloading scikit_learn-1.7.1-cp311-cp311-macosx_10_9_x86_64.whl (9.3 MB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 9.3/9.3 MB 23.9 MB/s eta 0:00:00
Collecting joblib>=1.0
  Using cached joblib-1.5.1-py3-none-any.whl (307 kB)
Collecting python-dotenv>=1.0.0
  Using cached python_dotenv-1.1.1-py3-none-any.whl (20 kB)
Collecting tabulate>=0.9.0
  Using cached tabulate-0.9.0-py3-none-any.whl (35 kB)
Collecting aiohttp>=3.8.0
  Downloading aiohttp-3.12.15-cp311-cp311-macosx_10_9_x86_64.whl (483 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 483.5/483.5 kB 10.4 MB/s eta 0:00:00
Collecting PyYAML>=6.0
  Using cached PyYAML-6.0.2-cp311-cp311-macosx_10_9_x86_64.whl (184 kB)
Collecting charset_normalizer<4,>=2
  Using cached charset_normalizer-3.4.2-cp311-cp311-macosx_10_9_universal2.whl (198 kB)
Collecting idna<4,>=2.5
  Using cached idna-3.10-py3-none-any.whl (70 kB)
Collecting urllib3<3,>=1.21.1
  Using cached urllib3-2.5.0-py3-none-any.whl (129 kB)
Collecting certifi>=2017.4.17
  Using cached certifi-2025.7.14-py3-none-any.whl (162 kB)
Collecting numpy>=1.22.0
  Using cached numpy-2.3.2-cp311-cp311-macosx_10_9_x86_64.whl (21.3 MB)
Collecting scipy>=1.8.0
  Downloading scipy-1.16.1-cp311-cp311-macosx_10_14_x86_64.whl (36.6 MB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 36.6/36.6 MB 27.3 MB/s eta 0:00:00
Collecting threadpoolctl>=3.1.0
  Downloading threadpoolctl-3.6.0-py3-none-any.whl (18 kB)
Collecting aiohappyeyeballs>=2.5.0
  Using cached aiohappyeyeballs-2.6.1-py3-none-any.whl (15 kB)
Collecting aiosignal>=1.4.0
  Using cached aiosignal-1.4.0-py3-none-any.whl (7.5 kB)
Collecting attrs>=17.3.0
  Using cached attrs-25.3.0-py3-none-any.whl (63 kB)
Collecting frozenlist>=1.1.1
  Using cached frozenlist-1.7.0-cp311-cp311-macosx_10_9_x86_64.whl (48 kB)
Collecting multidict<7.0,>=4.5
  Using cached multidict-6.6.3-cp311-cp311-macosx_10_9_x86_64.whl (44 kB)
Collecting propcache>=0.2.0
  Using cached propcache-0.3.2-cp311-cp311-macosx_10_9_x86_64.whl (43 kB)
Collecting yarl<2.0,>=1.17.0
  Using cached yarl-1.20.1-cp311-cp311-macosx_10_9_x86_64.whl (91 kB)
Collecting typing-extensions>=4.2
  Using cached typing_extensions-4.14.1-py3-none-any.whl (43 kB)
Installing collected packages: urllib3, typing-extensions, threadpoolctl, tabulate, PyYAML, python-dotenv, propcache, numpy, multidict, joblib, idna, frozenlist, colorama, click, charset_normalizer, certifi, attrs, aiohappyeyeballs, yarl, scipy, requests, aiosignal, scikit-learn, aiohttp
Successfully installed PyYAML-6.0.2 aiohappyeyeballs-2.6.1 aiohttp-3.12.15 aiosignal-1.4.0 attrs-25.3.0 certifi-2025.7.14 charset_normalizer-3.4.2 click-8.2.1 colorama-0.4.6 frozenlist-1.7.0 idna-3.10 joblib-1.5.1 multidict-6.6.3 numpy-2.3.2 propcache-0.3.2 python-dotenv-1.1.1 requests-2.32.4 scikit-learn-1.7.1 scipy-1.16.1 tabulate-0.9.0 threadpoolctl-3.6.0 typing-extensions-4.14.1 urllib3-2.5.0 yarl-1.20.1

[notice] A new release of pip available: 22.3 -> 25.1.1
[notice] To update, run: pip install --upgrade pip
Obtaining file:///Users/michaelraftery/gridland3
  Preparing metadata (setup.py) ... done
Requirement already satisfied: requests>=2.31.0 in ./venv/lib/python3.11/site-packages (from gridland==3.0.0) (2.32.4)
Requirement already satisfied: click>=8.1.0 in ./venv/lib/python3.11/site-packages (from gridland==3.0.0) (8.2.1)
Requirement already satisfied: colorama>=0.4.6 in ./venv/lib/python3.11/site-packages (from gridland==3.0.0) (0.4.6)
Requirement already satisfied: scikit-learn>=1.0 in ./venv/lib/python3.11/site-packages (from gridland==3.0.0) (1.7.1)
Requirement already satisfied: joblib>=1.0 in ./venv/lib/python3.11/site-packages (from gridland==3.0.0) (1.5.1)
Requirement already satisfied: python-dotenv>=1.0.0 in ./venv/lib/python3.11/site-packages (from gridland==3.0.0) (1.1.1)
Requirement already satisfied: tabulate>=0.9.0 in ./venv/lib/python3.11/site-packages (from gridland==3.0.0) (0.9.0)
Requirement already satisfied: aiohttp>=3.8.0 in ./venv/lib/python3.11/site-packages (from gridland==3.0.0) (3.12.15)
Requirement already satisfied: PyYAML>=6.0 in ./venv/lib/python3.11/site-packages (from gridland==3.0.0) (6.0.2)
Requirement already satisfied: aiohappyeyeballs>=2.5.0 in ./venv/lib/python3.11/site-packages (from aiohttp>=3.8.0->gridland==3.0.0) (2.6.1)
Requirement already satisfied: aiosignal>=1.4.0 in ./venv/lib/python3.11/site-packages (from aiohttp>=3.8.0->gridland==3.0.0) (1.4.0)
Requirement already satisfied: attrs>=17.3.0 in ./venv/lib/python3.11/site-packages (from aiohttp>=3.8.0->gridland==3.0.0) (25.3.0)
Requirement already satisfied: frozenlist>=1.1.1 in ./venv/lib/python3.11/site-packages (from aiohttp>=3.8.0->gridland==3.0.0) (1.7.0)
Requirement already satisfied: multidict<7.0,>=4.5 in ./venv/lib/python3.11/site-packages (from aiohttp>=3.8.0->gridland==3.0.0) (6.6.3)
Requirement already satisfied: propcache>=0.2.0 in ./venv/lib/python3.11/site-packages (from aiohttp>=3.8.0->gridland==3.0.0) (0.3.2)
Requirement already satisfied: yarl<2.0,>=1.17.0 in ./venv/lib/python3.11/site-packages (from aiohttp>=3.8.0->gridland==3.0.0) (1.20.1)
Requirement already satisfied: charset_normalizer<4,>=2 in ./venv/lib/python3.11/site-packages (from requests>=2.31.0->gridland==3.0.0) (3.4.2)
Requirement already satisfied: idna<4,>=2.5 in ./venv/lib/python3.11/site-packages (from requests>=2.31.0->gridland==3.0.0) (3.10)
Requirement already satisfied: urllib3<3,>=1.21.1 in ./venv/lib/python3.11/site-packages (from requests>=2.31.0->gridland==3.0.0) (2.5.0)
Requirement already satisfied: certifi>=2017.4.17 in ./venv/lib/python3.11/site-packages (from requests>=2.31.0->gridland==3.0.0) (2025.7.14)
Requirement already satisfied: numpy>=1.22.0 in ./venv/lib/python3.11/site-packages (from scikit-learn>=1.0->gridland==3.0.0) (2.3.2)
Requirement already satisfied: scipy>=1.8.0 in ./venv/lib/python3.11/site-packages (from scikit-learn>=1.0->gridland==3.0.0) (1.16.1)
Requirement already satisfied: threadpoolctl>=3.1.0 in ./venv/lib/python3.11/site-packages (from scikit-learn>=1.0->gridland==3.0.0) (3.6.0)
Requirement already satisfied: typing-extensions>=4.2 in ./venv/lib/python3.11/site-packages (from aiosignal>=1.4.0->aiohttp>=3.8.0->gridland==3.0.0) (4.14.1)
Installing collected packages: gridland
  Running setup.py develop for gridland
Successfully installed gridland-3.0.0

[notice] A new release of pip available: 22.3 -> 25.1.1
[notice] To update, run: pip install --upgrade pip
(venv)  michaelraftery@michaels-MacBook-Pro  ~/gridland3   feature/advanced-fingerprinting-1  pytest
============================================= test session starts =============================================
platform darwin -- Python 3.11.0, pytest-8.4.1, pluggy-1.6.0
rootdir: /Users/michaelraftery/gridland3
configfile: pytest.ini
testpaths: tests
plugins: anyio-4.9.0, asyncio-1.0.0
asyncio: mode=Mode.STRICT, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collected 6 items / 1 error                                                                                   

=================================================== ERRORS ====================================================
___________________________ ERROR collecting tests/test_enhanced_stream_scanner.py ____________________________
ImportError while importing test module '/Users/michaelraftery/gridland3/tests/test_enhanced_stream_scanner.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/Library/Frameworks/Python.framework/Versions/3.11/lib/python3.11/importlib/__init__.py:126: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_enhanced_stream_scanner.py:5: in <module>
    from gridland.analyze.plugins.builtin.enhanced_stream_scanner import EnhancedStreamScanner
src/gridland/analyze/plugins/builtin/enhanced_stream_scanner.py:29: in <module>
    from gridland.analyze.core.models import StreamPlugin, PluginMetadata, StreamResult
E   ModuleNotFoundError: No module named 'gridland.analyze.core.models'
=========================================== short test summary info ===========================================
ERROR tests/test_enhanced_stream_scanner.py
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Interrupted: 1 error during collection !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
============================================== 1 error in 2.24s ===============================================
(venv)  ✘ michaelraftery@michaels-MacBook-Pro  ~/gridland3   feature/advanced-fingerprinting-1  cd
(venv)  michaelraftery@michaels-MacBook-Pro  ~  cd gridland3
(venv)  michaelraftery@michaels-MacBook-Pro  ~/gridland3   feature/advanced-fingerprinting-1  PYTHONPATH=src pytest
============================================= test session starts =============================================
platform darwin -- Python 3.11.0, pytest-8.4.1, pluggy-1.6.0
rootdir: /Users/michaelraftery/gridland3
configfile: pytest.ini
testpaths: tests
plugins: anyio-4.9.0, asyncio-1.0.0
asyncio: mode=Mode.STRICT, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collected 6 items / 1 error                                                                                   

=================================================== ERRORS ====================================================
___________________________ ERROR collecting tests/test_enhanced_stream_scanner.py ____________________________
ImportError while importing test module '/Users/michaelraftery/gridland3/tests/test_enhanced_stream_scanner.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/Library/Frameworks/Python.framework/Versions/3.11/lib/python3.11/importlib/__init__.py:126: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_enhanced_stream_scanner.py:5: in <module>
    from gridland.analyze.plugins.builtin.enhanced_stream_scanner import EnhancedStreamScanner
src/gridland/analyze/plugins/builtin/enhanced_stream_scanner.py:29: in <module>
    from gridland.analyze.core.models import StreamPlugin, PluginMetadata, StreamResult
E   ModuleNotFoundError: No module named 'gridland.analyze.core.models'
=========================================== short test summary info ===========================================
ERROR tests/test_enhanced_stream_scanner.py
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Interrupted: 1 error during collection !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
============================================== 1 error in 1.55s ===============================================
(venv)  ✘ michaelraftery@michaels-MacBook-Pro  ~/gridland3   feature/advanced-fingerprinting-1  touch tests/conftest.py
(venv)  michaelraftery@michaels-MacBook-Pro  ~/gridland3   feature/advanced-fingerprinting-1  pytest
============================================= test session starts =============================================
platform darwin -- Python 3.11.0, pytest-8.4.1, pluggy-1.6.0
rootdir: /Users/michaelraftery/gridland3
configfile: pytest.ini
testpaths: tests
plugins: anyio-4.9.0, asyncio-1.0.0
asyncio: mode=Mode.STRICT, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collected 6 items / 1 error                                                                                   

=================================================== ERRORS ====================================================
___________________________ ERROR collecting tests/test_enhanced_stream_scanner.py ____________________________
ImportError while importing test module '/Users/michaelraftery/gridland3/tests/test_enhanced_stream_scanner.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/Library/Frameworks/Python.framework/Versions/3.11/lib/python3.11/importlib/__init__.py:126: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_enhanced_stream_scanner.py:5: in <module>
    from gridland.analyze.plugins.builtin.enhanced_stream_scanner import EnhancedStreamScanner
src/gridland/analyze/plugins/builtin/enhanced_stream_scanner.py:29: in <module>
    from gridland.analyze.core.models import StreamPlugin, PluginMetadata, StreamResult
E   ModuleNotFoundError: No module named 'gridland.analyze.core.models'
=========================================== short test summary info ===========================================
ERROR tests/test_enhanced_stream_scanner.py
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Interrupted: 1 error during collection !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
============================================== 1 error in 1.40s ===============================================
(venv)  ✘ michaelraftery@michaels-MacBook-Pro  ~/gridland3   feature/advanced-fingerprinting-1  pytest
============================================= test session starts =============================================
platform darwin -- Python 3.11.0, pytest-8.4.1, pluggy-1.6.0
rootdir: /Users/michaelraftery/gridland3
configfile: pytest.ini
testpaths: tests
plugins: anyio-4.9.0, asyncio-1.0.0
asyncio: mode=Mode.STRICT, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collected 9 items                                                                                             

tests/test_enhanced_camera_detector.py ...ss                                                            [ 55%]
tests/test_enhanced_stream_scanner.py .FF                                                               [ 88%]
tests/test_fingerprinting_parsers.py .                                                                  [100%]

================================================== FAILURES ===================================================
___________________________________________ test_test_rtsp_streams ____________________________________________

scanner_instance = <gridland.analyze.plugins.builtin.enhanced_stream_scanner.EnhancedStreamScanner object at 0x1242379d0>

/Library/Frameworks/Python.framework/Versions/3.11/lib/python3.11/re/_parser.py:581: RuntimeWarning: coroutine 'mock_get' was never awaited
  code1 = LITERAL, _ord(this)
RuntimeWarning: Enable tracemalloc to get the object allocation traceback
    @pytest.mark.asyncio
    async def test_test_rtsp_streams(scanner_instance):
        """
        Tests if the _test_rtsp_streams method correctly identifies RTSP streams.
        """
        scanner_instance._test_rtsp_endpoint = AsyncMock(return_value=(True, False, {}))
>       streams = await scanner_instance._test_rtsp_streams("127.0.0.1", 554, "hikvision")
                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       TypeError: EnhancedStreamScanner._test_rtsp_streams() missing 1 required positional argument: 'service'

tests/test_enhanced_stream_scanner.py:52: TypeError
___________________________________________ test_test_http_streams ____________________________________________

scanner_instance = <gridland.analyze.plugins.builtin.enhanced_stream_scanner.EnhancedStreamScanner object at 0x122670c50>

    @pytest.mark.asyncio
    async def test_test_http_streams(scanner_instance):
        """
        Tests if the _test_http_streams method correctly identifies HTTP streams.
        """
        # ... (mock response setup is correct) ...
    
        mock_session = MagicMock()
        mock_session.get = AsyncMock(return_value=mock_get()) # Use AsyncMock for async methods
    
        # --- THIS IS THE FIX ---
        # The following line had an extra indent, causing the SyntaxError.
        # It has been corrected to align with the 'mock_session' line.
        scanner_instance._validate_http_stream = AsyncMock(return_value=StreamEndpoint(
            url="http://127.0.0.1:80/snapshot.jpg",
            protocol="http",
            brand="generic",
            content_type="image/jpeg",
            response_size=1024,
            authentication_required=False,
            confidence=0.9,
            response_time=100,
            quality_score=0.8,
            metadata={}
        ))
        # --- END OF FIX ---
    
        # We now pass the mock session into the method
        streams = await scanner_instance._test_http_streams(mock_session, "127.0.0.1", 80, "generic")
    
>       assert len(streams) > 0
E       assert 0 > 0
E        +  where 0 = len([])

tests/test_enhanced_stream_scanner.py:86: AssertionError
=========================================== short test summary info ===========================================
FAILED tests/test_enhanced_stream_scanner.py::test_test_rtsp_streams - TypeError: EnhancedStreamScanner._test_rtsp_streams() missing 1 required positional argument: 'service'
FAILED tests/test_enhanced_stream_scanner.py::test_test_http_streams - assert 0 > 0
=================================== 2 failed, 5 passed, 2 skipped in 1.21s ====================================
(venv)  ✘ michaelraftery@michaels-MacBook-Pro  ~/gridland3   feature/advanced-fingerprinting-1  

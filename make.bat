@ECHO OFF

REM Command file for Sphinx documentation

set SPHINXBUILD=sphinx-build
set ALLSPHINXOPTS=-d sph_build/doctrees %SPHINXOPTS% .
if NOT "%PAPER%" == "" (
	set ALLSPHINXOPTS=-D latex_paper_size=%PAPER% %ALLSPHINXOPTS%
)

if "%1" == "" goto help

if "%1" == "help" (
	:help
	echo.Please use `make ^<target^>` where ^<target^> is one of
	echo.  html      to make standalone HTML files
	echo.  dirhtml   to make HTML files named index.html in directories
	echo.  pickle    to make pickle files
	echo.  json      to make JSON files
	echo.  htmlhelp  to make HTML files and a HTML help project
	echo.  qthelp    to make HTML files and a qthelp project
	echo.  latex     to make LaTeX files, you can set PAPER=a4 or PAPER=letter
	echo.  changes   to make an overview over all changed/added/deprecated items
	echo.  linkcheck to check all external links for integrity
	echo.  doctest   to run all doctests embedded in the documentation if enabled
	goto end
)

if "%1" == "clean" (
	for /d %%i in (sph_build\*) do rmdir /q /s %%i
	del /q /s sph_build\*
	goto end
)

if "%1" == "html" (
	%SPHINXBUILD% -b html %ALLSPHINXOPTS% sph_build/html
	echo.
	echo.Build finished. The HTML pages are in sph_build/html.
	goto end
)

if "%1" == "dirhtml" (
	%SPHINXBUILD% -b dirhtml %ALLSPHINXOPTS% sph_build/dirhtml
	echo.
	echo.Build finished. The HTML pages are in sph_build/dirhtml.
	goto end
)

if "%1" == "pickle" (
	%SPHINXBUILD% -b pickle %ALLSPHINXOPTS% sph_build/pickle
	echo.
	echo.Build finished; now you can process the pickle files.
	goto end
)

if "%1" == "json" (
	%SPHINXBUILD% -b json %ALLSPHINXOPTS% sph_build/json
	echo.
	echo.Build finished; now you can process the JSON files.
	goto end
)

if "%1" == "htmlhelp" (
	%SPHINXBUILD% -b htmlhelp %ALLSPHINXOPTS% sph_build/htmlhelp
	echo.
	echo.Build finished; now you can run HTML Help Workshop with the ^
.hhp project file in sph_build/htmlhelp.
	goto end
)

if "%1" == "qthelp" (
	%SPHINXBUILD% -b qthelp %ALLSPHINXOPTS% sph_build/qthelp
	echo.
	echo.Build finished; now you can run "qcollectiongenerator" with the ^
.qhcp project file in sph_build/qthelp, like this:
	echo.^> qcollectiongenerator sph_build\qthelp\PyECC.qhcp
	echo.To view the help file:
	echo.^> assistant -collectionFile sph_build\qthelp\PyECC.ghc
	goto end
)

if "%1" == "latex" (
	%SPHINXBUILD% -b latex %ALLSPHINXOPTS% sph_build/latex
	echo.
	echo.Build finished; the LaTeX files are in sph_build/latex.
	goto end
)

if "%1" == "changes" (
	%SPHINXBUILD% -b changes %ALLSPHINXOPTS% sph_build/changes
	echo.
	echo.The overview file is in sph_build/changes.
	goto end
)

if "%1" == "linkcheck" (
	%SPHINXBUILD% -b linkcheck %ALLSPHINXOPTS% sph_build/linkcheck
	echo.
	echo.Link check complete; look for any errors in the above output ^
or in sph_build/linkcheck/output.txt.
	goto end
)

if "%1" == "doctest" (
	%SPHINXBUILD% -b doctest %ALLSPHINXOPTS% sph_build/doctest
	echo.
	echo.Testing of doctests in the sources finished, look at the ^
results in sph_build/doctest/output.txt.
	goto end
)

:end

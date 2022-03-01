*********
Changelog
*********

1.2.0 (2022-03-01)
------------------

- Make git submodules fetching configurable
- Fix source type specification
- Fix testing in Python 3.10
- Address issues found by linters

1.1.2 (2022-02-07)
------------------

- Do not refresh already installed snaps
- Fix URL in setup.py
- Fix pydantic validation error handling
- Unpin pydantic and pydantic-yaml dependency versions
- Unpin pylint dependency version
- Remove unused requirements files

1.1.1 (2022-01-05)
------------------

- Pin pydantic and pydantic-yaml dependency versions

1.1.0 (2021-12-08)
------------------

- Add support to overlay step
- Use bash as step scriptlet interpreter
- Add plugin environment validation
- Add go plugin
- Add dotnet plugin

1.0.4 (2021-11-10)
------------------

- Declare additional public API names
- Add git source handler

1.0.3 (2021-10-19)
------------------

- Properly declare public API names
- Allow non-snap applications running on non-apt systems to invoke parts
  processing on build providers
- Use Bash as script interpreter instead of /bin/sh to stay compatible
  with Snapcraft V2 plugins

1.0.2 (2021-09-16)
------------------

- Fix local source updates causing removal of build artifacts and new
  files created in ``override-pull``

1.0.1 (2021-09-13)
------------------

- Fix plugin properties test
- Use local copy of mutable source handler ignore patterns
- Use host state for apt cache and remove stage package refresh
- Add information to parts error in CLI tool
- Change CLI tool ``--debug`` option to ``--trace`` to be consistent
  with craft tools


1.0.0 (2021-08-05)
------------------

- Initial release
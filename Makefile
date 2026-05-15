.PHONY: help prepare-dev test test-integration lint build-dist release-preflight github-release release release-test

VENV_NAME?=venv
VENV_ACTIVATE=. $(VENV_NAME)/bin/activate
PYTHON=${VENV_NAME}/bin/python3

help:
	@echo "make prepare-dev"
	@echo "       prepare development environment, use only once"
	@echo "make test"
	@echo "       run offline tests"
	@echo "make test-integration"
	@echo "       run live integration tests"
	@echo "make lint"
	@echo "       run pylint and mypy"
	@echo "make build-dist"
	@echo "       build wheel and sdist locally, then validate them with twine"
	@echo "make release-preflight"
	@echo "       verify gh auth and a matching git tag before a synced release"
	@echo "make github-release"
	@echo "       create or update the matching GitHub release from local dist/*"
	@echo "make release"
	@echo "       upload the current version to PyPI and sync the GitHub release"
	@echo "make release-test"
	@echo "       upload the current version to TestPyPI from the local machine"
	@echo "tag the release commit as 0.6.4 or v0.6.4 before make release"
	@echo "       GitHub workflows do not publish to PyPI"

prepare-dev:
	sudo apt-get -y install python3 python3-pip
	python3 -m pip install virtualenv
	make venv

venv: $(VENV_NAME)/bin/activate

$(VENV_NAME)/bin/activate: setup.py
	test -d $(VENV_NAME) || virtualenv -p python3 $(VENV_NAME)
	${PYTHON} -m pip install -U pip
	${PYTHON} -m pip install -r requirements.txt
	touch $(VENV_NAME)/bin/activate

test: venv
	${PYTHON} -m pytest -v

test-integration: venv
	${PYTHON} -m pytest -m integration -v

build-dist:
	rm -rf ./dist/*
	${PYTHON} -m pip install --upgrade -r requirements-release.txt
	${PYTHON} setup.py sdist bdist_wheel
	${PYTHON} -m twine check dist/*

release-preflight:
	@VERSION="$$( ${PYTHON} -c 'from valhallaAPI.version import __version__; print(__version__)' )"; \
	if git rev-parse -q --verify "refs/tags/$$VERSION" >/dev/null 2>&1; then \
		TAG_NAME="$$VERSION"; \
	elif git rev-parse -q --verify "refs/tags/v$$VERSION" >/dev/null 2>&1; then \
		TAG_NAME="v$$VERSION"; \
	else \
		echo "Missing git tag for version $$VERSION. Create 0.6.4 or v0.6.4 before releasing."; \
		exit 1; \
	fi; \
	if ! git tag --points-at HEAD | grep -Fx "$$TAG_NAME" >/dev/null 2>&1; then \
		echo "Tag $$TAG_NAME does not point at HEAD."; \
		exit 1; \
	fi; \
	if ! command -v gh >/dev/null 2>&1; then \
		echo "gh CLI is required to create the GitHub release."; \
		exit 1; \
	fi; \
	if ! gh auth status >/dev/null 2>&1; then \
		echo "gh CLI is not authenticated."; \
		exit 1; \
	fi

github-release: release-preflight
	@VERSION="$$( ${PYTHON} -c 'from valhallaAPI.version import __version__; print(__version__)' )"; \
	if git rev-parse -q --verify "refs/tags/$$VERSION" >/dev/null 2>&1; then \
		TAG_NAME="$$VERSION"; \
	else \
		TAG_NAME="v$$VERSION"; \
	fi; \
	if gh release view "$$TAG_NAME" >/dev/null 2>&1; then \
		gh release upload "$$TAG_NAME" dist/* --clobber; \
	else \
		gh release create "$$TAG_NAME" dist/* --generate-notes --title "$$TAG_NAME"; \
	fi

release: release-preflight build-dist
	${PYTHON} -m twine upload dist/*
	$(MAKE) github-release

release-test: build-dist
	${PYTHON} -m twine upload --repository-url https://test.pypi.org/legacy/ dist/*

lint: venv
	${PYTHON} -m pylint
	${PYTHON} -m mypy

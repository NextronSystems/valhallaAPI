.PHONY: help prepare-dev test lint release

VENV_NAME?=venv
VENV_ACTIVATE=. $(VENV_NAME)/bin/activate
PYTHON=${VENV_NAME}/bin/python3

help:
	@echo "make prepare-dev"
	@echo "       prepare development environment, use only once"
	@echo "make test"
	@echo "       run tests"
	@echo "make lint"
	@echo "       run pylint and mypy"

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

release:
	${PYTHON} -m pip install --upgrade setuptools wheel
	${PYTHON} -m pip install --upgrade twine
	${PYTHON} -m twine check dist/*
	${PYTHON} -m twine upload dist/*

lint: venv
	${PYTHON} -m pylint
	${PYTHON} -m mypy





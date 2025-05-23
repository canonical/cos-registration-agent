.PHONY: help
help:             ## Show the help.
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@fgrep "##" Makefile | fgrep -v fgrep

.PHONY: install
install:          ## Install the project in dev mode.
	@echo "Don't forget to run 'make virtualenv' if you got errors."
	pip install -e .[test]

.PHONY: fmt
fmt:              ## Format code using black & isort.
	isort cos_registration_agent/
	black -l 79 cos_registration_agent/
	black -l 79 tests/

.PHONY: lint
lint:             ## Run pep8, black, mypy linters.
	mypy --ignore-missing-imports cos_registration_agent/
	flake8 --ignore=D104 --inline-quotes '"' cos_registration_agent/
	black --check --diff -l 79 cos_registration_agent/ tests/

.PHONY: test
test: lint        ## Run tests and generate coverage report.
	pytest -vv --cov-config .coveragerc --cov=cos_registration_agent -l --tb=short --maxfail=1 tests/
	coverage xml
	coverage html

.PHONY: watch
watch:            ## Run tests on every change.
	ls **/**.py | entr pytest -s -vvv -l --tb=long --maxfail=1 tests/

.PHONY: clean
clean:            ## Clean unused files.
	@find ./ -name '*.pyc' -exec rm -f {} \;
	@find ./ -name '__pycache__' -exec rm -rf {} \;
	@find ./ -name 'Thumbs.db' -exec rm -f {} \;
	@find ./ -name '*~' -exec rm -f {} \;
	@rm -rf .cache
	@rm -rf .pytest_cache
	@rm -rf .mypy_cache
	@rm -rf build
	@rm -rf dist
	@rm -rf *.egg-info
	@rm -rf htmlcov
	@rm -rf .tox/
	@rm -rf docs/_build

.PHONY: virtualenv
virtualenv:       ## Create a virtual environment.
	@echo "creating virtualenv ..."
	@rm -rf .venv
	@python3 -m venv .venv
	@./.venv/bin/pip install -U pip
	@./.venv/bin/pip install -e .[test]
	@echo
	@echo "!!! Please run 'source .venv/bin/activate' to enable the environment !!!"

.PHONY: release
release:          ## Create a new tag for release.
	@echo "WARNING: This operation will create s version tag and push to github"
	@read -p "Version? (provide the next x.y.z semver) : " TAG
	@echo "$${TAG}" > cos_registration_agent/VERSION
	@gitchangelog > HISTORY.md
	@git add cos_registration_agent/VERSION HISTORY.md
	@git commit -m "release: version $${TAG} 🚀"
	@echo "creating git tag : $${TAG}"
	@git tag $${TAG}
	@git push -u origin HEAD --tags
	@echo "Github Actions will detect the new tag and release the new version."

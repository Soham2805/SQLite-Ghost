from setuptools import setup, find_packages

setup(
    name='sqlite-ghost',
    version='0.1.0',
    description='A schema-agnostic Python framework designed to carve deleted records and analyze SQLite databases.',
    packages=find_packages(),
    install_requires=[
        'click',
        'jinja2',
    ],
    entry_points={
        'console_scripts': [
            'sqlite-ghost=sqlite_ghost.cli:cli',
        ],
    },
)

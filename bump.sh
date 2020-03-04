cd /Users/pcotton/github/muid/
rm /Users/pcotton/github/muid/dist/*
python setup.py sdist bdist_wheel
twine upload dist/*

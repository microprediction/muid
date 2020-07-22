mkdir mining_working_dir
cd mining_working_dir
python3 -m venv miningenv
source miningenv/bin/activate
pip install --upgrade muid
python3 -c "import muid;muid.mine()"
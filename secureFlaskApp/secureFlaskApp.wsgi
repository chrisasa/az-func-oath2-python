import sys
import pathlib
import os 

root_function_dir = pathlib.Path(__file__).parent.parent
secureFlaskApp_path = os.path.join( root_function_dir, "secureFlaskApp")
sys.path.insert(0, secureFlaskApp_path)
from secureFlaskApp import app as application
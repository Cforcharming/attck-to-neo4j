import sys
from db_init import db_init
from db_update import db_update

if __name__ == "__main__":
    
    working_dir = sys.argv[0].strip("main.py")
    if len(sys.argv) > 1:
        operation = sys.argv[1]
    else:
        print("operation not specified, call update.")
        operation = "update"
        
    if operation == "init":
        db_init()
        
    else:
        if operation != "update":
            print("operation not specified, call update.")
            
        db_update(working_dir)

from db_init import db_init
import git


def db_update(working_dir):
    """version 1.2 use git pull to update cti directory, then call db_init()"""
    cti = working_dir + "cti"
    origin = git.Repo.init(cti).remote("origin")
    origin.pull()
    print("db up to date.")

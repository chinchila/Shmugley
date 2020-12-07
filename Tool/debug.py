import sys

_level = 0
_out_file = None

def set_level(level):
    global _level
    _level = level
    

def set_out_file(file):
    global _out_file
    _out_file = file

def info( string ):
    global _out_file
    print( f"INFO: {string}" )
    if _out_file is not None:
        _out_file.write( f"{string}\n" )

def error( string ):
    global _out_file
    print( f"ERROR: {string}" )
    if _out_file is not None:
        _out_file.write( f"{string}\n" )
    sys.exit(1)

def show( string ):
    global _out_file
    print( f"{string}" )
    if _out_file is not None:
        _out_file.write( f"{string}\n" )

def show_verbose( string, lev ):
    global _out_file, _level
    if _level >= lev:
        print( f"{string}" )
        if _out_file is not None:
            _out_file.write( f"{string}\n" )


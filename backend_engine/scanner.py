import os

class BaseScanner:
    #Base class for all infrastructure code scanners.
    def __init__(self,filepath):
        self.filpathath = filepath

    def scan(self):
        raise NotImplementedError("ubclasses must implement the scan() method.")
    def remidate(self,line_number,new_content):
        #rewrites a speicifc line in te target file to fix a vulnerbility
        if not os.path.exists(self.filepath):
            return False
        
        with open(self.filepath, 'r') as f:
            lines = f.readlines()

        if 0 < line_number <=len(lines):
            lines[line_number-1]=new_content + '\n'

            with open(self.filepath, 'w') as f:
                f.writelines(lines)
            return True
        return False


        

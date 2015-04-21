# Creates a class called SLAAC_Message
import logging

class S3Log:
    def __init__(self):
        self.name = "Hello"
    def writelog(self,message,logfile):
        logging.basicConfig(filename=logfile,format='%(levelname)s:%(asctime)s: %(message)s',level=logging.INFO)
        logging.info(message)



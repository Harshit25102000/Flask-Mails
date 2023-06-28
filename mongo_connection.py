import pymongo

client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client['outh-test']
cred_db = db['credentials']

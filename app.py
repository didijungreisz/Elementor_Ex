import json
from flask import Flask
import sqlite3
from csv import reader
from api import scan_url

app = Flask(__name__)
@app.before_request
def before_request():
    con = sqlite3.connect('sites.db', check_same_thread=False)
    with con:
        cur = con.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS sites_info(url TEXT, risk_categorized TEXT, total_votes TEXT, 
                        categories_classification TEXT, last_modified LONG)""")
        cur.execute("CREATE INDEX IF NOT EXISTS url_ind ON sites_info(url)")
        cur.execute("CREATE TABLE IF NOT EXISTS requests(url TEXT, time LONG)")
        con.commit()

@app.route("/scan_sites_from_csv/")
def sites_from_csv():
        l = list()
        with open('sites/request1.csv', 'r') as file:
            csv_file_reader = reader(file)
            for url_to_check in csv_file_reader:
                l.append(json.dumps(scan_url(url_to_check[0])).replace('"', '')[1:-1])
            return '<br>'.join(l)

@app.route("/scan_single_site/<site>")
def scan_single_site(site):
        return json.dumps(scan_url(site)).replace('"', '')[1:-1]
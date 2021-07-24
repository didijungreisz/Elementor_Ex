import base64
import json
import time
import sqlite3
import requests

HEADERS = {
    "x-apikey": "dd961fdb38920944cfd70236fa0f60546762bcec50ca775af19c2166dc08d3ed",
}
risks_list = ['malicious', 'phishing', 'malware']
up_to_date_sec = 1800
con = sqlite3.connect('sites.db', check_same_thread=False)

def scan_url(url):
    con.row_factory = __dict_factory
    curr_time = int(time.time())
    cur = con.cursor()
    cur.execute(f"INSERT INTO requests VALUES('{url}',{curr_time})")
    con.commit()
    cur.execute(f"""SELECT url, risk_categorized, total_votes, categories_classification, last_modified FROM sites_info 
                    WHERE url = '{url}'""")
    site_data = cur.fetchone()
    if not site_data:
        site_data = vt_site_check(url)
        __insert_data_to_db(cur, site_data, curr_time)
    elif curr_time - site_data['last_modified'] > up_to_date_sec:
        site_data = vt_site_check(url)
        __update_data_in_db(cur, site_data, curr_time)
    else:
        del site_data['last_modified']
    return site_data


def vt_site_check(url):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    req = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=HEADERS).json()

    results = req['data']['attributes']['last_analysis_results']
    categories = req['data']['attributes']['categories']
    risk = 0
    votes = {}
    result = {}
    cats = {}
    for site_check in results.keys():
        risk_result = results[site_check]['result']
        if risk_result in risks_list:
            risk += 1
        if risk_result in votes:
            votes[risk_result] += 1
        else:
            votes[risk_result] = 1
    for category in categories.values():
        if category in cats:
            cats[category] += 1
        else:
            cats[category] = 1

    result['url'] = url
    result['risk_categorized'] = 'risk' if risk > 1 else 'safe'
    result['total_votes'] = json.dumps(votes).replace('"', '')
    result['categories_classification'] = json.dumps(cats).replace('"', '')
    return result


def __dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


def __insert_data_to_db(cur, site_data, curr_time):
    cur.execute(f"""INSERT INTO sites_info VALUES('{site_data['url']}','{site_data['risk_categorized']}',
    '{site_data['total_votes']}','{site_data['categories_classification']}',{curr_time})""")
    con.commit()


def __update_data_in_db(cur, site_data, curr_time):
    cur.execute(f"""UPDATE sites_info SET (risk_categorized, total_votes, categories_classification, last_modified) 
        = ('{site_data['risk_categorized']}', '{site_data['total_votes']}','{site_data['categories_classification']}',
            {curr_time}) WHERE url = '{site_data['url']}'""")
    con.commit()

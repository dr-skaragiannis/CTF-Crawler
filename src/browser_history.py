"""Export Firefox / Chrome / Chromium / Brave history and downloads since a given time.

Installed by ctf-logger as /etc/ctf-logger/browser_history.py and run by it periodically:
    python3 browser_history.py <since-epoch> <output-file> <home> [<home> ...]
The browser databases are copied first, so this works while the browsers are running.
"""
import glob
import os
import shutil
import sqlite3
import sys
import tempfile
import time

CHROME_EPOCH = 11644473600  # seconds between 1601-01-01 and 1970-01-01

FIREFOX_VISIT = {1: "link", 2: "typed", 3: "bookmark", 4: "embed", 5: "redirect",
                 6: "redirect", 7: "download", 8: "frame", 9: "reload"}
CHROME_VISIT = {0: "link", 1: "typed", 2: "bookmark", 3: "frame", 4: "frame", 5: "generated",
                6: "start", 7: "form", 8: "reload", 9: "keyword", 10: "keyword"}

FIREFOX_DIRS = [".mozilla/firefox", ".mozilla/firefox-esr", "snap/firefox/common/.mozilla/firefox"]
CHROME_DIRS = {"chrome": ".config/google-chrome", "chromium": ".config/chromium",
               "brave": ".config/BraveSoftware/Brave-Browser"}


def query(db, sql, args):
    tmp = tempfile.mkdtemp(prefix="ctf-hist-")
    try:
        for ext in ("", "-wal", "-shm", "-journal"):
            if os.path.exists(db + ext):
                shutil.copy2(db + ext, os.path.join(tmp, "db" + ext))
        con = sqlite3.connect(os.path.join(tmp, "db"))
        try:
            return con.execute(sql, args).fetchall()
        finally:
            con.close()
    except sqlite3.Error:
        return []
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def firefox(home, since, rows):
    for base in FIREFOX_DIRS:
        for db in glob.glob(os.path.join(home, base, "*", "places.sqlite")):
            profile = "firefox:" + os.path.basename(os.path.dirname(db))
            for t, url, title, kind in query(db, """
                    SELECT v.visit_date / 1000000.0, p.url, IFNULL(p.title, ''), v.visit_type
                    FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id
                    WHERE v.visit_date >= ?""", (int(since * 1e6),)):
                rows.append((t, profile, FIREFOX_VISIT.get(kind, "visit"), url, title))
            for t, url, dest in query(db, """
                    SELECT a.dateAdded / 1000000.0, p.url, a.content
                    FROM moz_annos a
                    JOIN moz_anno_attributes n ON n.id = a.anno_attribute_id
                    JOIN moz_places p ON p.id = a.place_id
                    WHERE n.name = 'downloads/destinationFileURI' AND a.dateAdded >= ?""",
                                      (int(since * 1e6),)):
                rows.append((t, profile, "DOWNLOAD", url, "-> " + dest))


def chrome(home, since, rows):
    chrome_since = int((since + CHROME_EPOCH) * 1e6)
    for name, base in CHROME_DIRS.items():
        for db in glob.glob(os.path.join(home, base, "*", "History")):
            profile = name + ":" + os.path.basename(os.path.dirname(db))
            for t, url, title, kind in query(db, """
                    SELECT v.visit_time / 1000000.0 - ?, u.url, IFNULL(u.title, ''), v.transition
                    FROM visits v JOIN urls u ON u.id = v.url
                    WHERE v.visit_time >= ?""", (CHROME_EPOCH, chrome_since)):
                rows.append((t, profile, CHROME_VISIT.get(kind & 0xFF, "visit"), url, title))
            for t, url, dest, size in query(db, """
                    SELECT d.start_time / 1000000.0 - ?,
                           (SELECT c.url FROM downloads_url_chains c WHERE c.id = d.id
                            ORDER BY c.chain_index DESC LIMIT 1),
                           d.target_path, d.received_bytes
                    FROM downloads d WHERE d.start_time >= ?""", (CHROME_EPOCH, chrome_since)):
                rows.append((t, profile, "DOWNLOAD", url or "", "-> %s (%s bytes)" % (dest, size)))


def main():
    since, out, homes = float(sys.argv[1]), sys.argv[2], sys.argv[3:]
    rows = []
    for home in homes:
        firefox(home, since, rows)
        chrome(home, since, rows)
    rows.sort()
    with open(out + ".tmp", "w", encoding="utf-8") as f:
        f.write("# time\tbrowser:profile\ttype\turl\ttitle / download target\n")
        for t, profile, kind, url, extra in rows:
            stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))
            f.write("%s\t%s\t%s\t%s\t%s\n" % (stamp, profile, kind, url, extra))
    os.replace(out + ".tmp", out)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
make_shards.py - turns a CSV of shops into the small files that Matchqach loads on demand.

    pip install cryptography
    python make_shards.py shops.csv --out data --base https://YOUR-PAGE-LINK

Writes:
  data/index.json            wilaya counts (the page reads this first)
  data/w<code>-<part>.json   the shops, 5000 per part, compact rows
  links.csv                  one private edit link per NEW shop (send each link to its owner only)
  keys.csv                   private keys of every shop. KEEP IT SECRET AND SAFE: it lets you
                             re-run this script without invalidating links already sent.

CSV columns (header row required, UTF-8):
  name, owner, phone, address, wilaya, daira, baladiya, map, cat, wa, kind, prices, note,
  open, close, off_days, paused
  wilaya   : Arabic name, French name, or number 1-58
  kind     : service | shop | product | goods
  open/close: HH:MM        off_days: e.g. 5 or "5,6" (0=Sunday ... 6=Saturday)    paused: 0 or 1
Shop ids are p<wilaya code>_<line number inside that wilaya>. Only append new rows at the end of
the CSV when you re-run, so existing ids and links stay valid.
"""
import argparse, base64, csv, json, os, re, sys
from cryptography.hazmat.primitives.asymmetric import ec

AR = ["أدرار", "الشلف", "الأغواط", "أم البواقي", "باتنة", "بجاية", "بسكرة", "بشار", "البليدة", "البويرة", "تمنراست", "تبسة", "تلمسان", "تيارت", "تيزي وزو", "الجزائر", "الجلفة", "جيجل", "سطيف", "سعيدة", "سكيكدة", "سيدي بلعباس", "عنابة", "قالمة", "قسنطينة", "المدية", "مستغانم", "المسيلة", "معسكر", "ورقلة", "وهران", "البيض", "إليزي", "برج بوعريريج", "بومرداس", "الطارف", "تندوف", "تيسمسيلت", "الوادي", "خنشلة", "سوق أهراس", "تيبازة", "ميلة", "عين الدفلى", "النعامة", "عين تموشنت", "غرداية", "غليزان", "تيميمون", "برج باجي مختار", "أولاد جلال", "بني عباس", "عين صالح", "عين قزام", "تقرت", "جانت", "المغير", "المنيعة"]
FR = ["Adrar", "Chlef", "Laghouat", "Oum El Bouaghi", "Batna", "Béjaïa", "Biskra", "Béchar", "Blida", "Bouira", "Tamanrasset", "Tébessa", "Tlemcen", "Tiaret", "Tizi Ouzou", "Alger", "Djelfa", "Jijel", "Sétif", "Saïda", "Skikda", "Sidi Bel Abbès", "Annaba", "Guelma", "Constantine", "Médéa", "Mostaganem", "M’Sila", "Mascara", "Ouargla", "Oran", "El Bayadh", "Illizi", "Bordj Bou Arréridj", "Boumerdès", "El Tarf", "Tindouf", "Tissemsilt", "El Oued", "Khenchela", "Souk Ahras", "Tipaza", "Mila", "Aïn Defla", "Naâma", "Aïn Témouchent", "Ghardaïa", "Relizane", "Timimoun", "Bordj Badji Mokhtar", "Ouled Djellal", "Béni Abbès", "In Salah", "In Guezzam", "Touggourt", "Djanet", "El Meghaier", "El Menia"]
KINDS = {'service': 0, 'shop': 1, 'product': 2, 'goods': 3, 'خدمة': 0, 'محل': 1, 'منتج': 2, 'سلعة': 3}
LIM = {'name': 80, 'owner': 80, 'phone': 20, 'address': 160, 'daira': 60, 'baladiya': 60, 'map': 500, 'prices': 300, 'note': 150}
PART = 5000
CTRL = re.compile(r'[\x00-\x1f\x7f‎‏‪-‮⁦-⁩]')


def b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip('=')


def txt(v, n):
    return re.sub(r'\s+', ' ', CTRL.sub(' ', v or '')).strip()[:n]


def wilaya_code(v):
    v = (v or '').strip()
    if v.isdigit() and 1 <= int(v) <= 58:
        return int(v)
    for i, (a, f) in enumerate(zip(AR, FR)):
        if v == a or v.lower() == f.lower():
            return i + 1
    return 0


def new_key():
    k = ec.generate_private_key(ec.SECP256R1())
    n = k.private_numbers()
    return (b64u(n.private_value.to_bytes(32, 'big')), b64u(n.public_numbers.x.to_bytes(32, 'big')),
            b64u(n.public_numbers.y.to_bytes(32, 'big')))


def pub_of(d):
    n = ec.derive_private_key(int.from_bytes(base64.urlsafe_b64decode(d + '=='), 'big'), ec.SECP256R1()).private_numbers()
    return b64u(n.public_numbers.x.to_bytes(32, 'big')), b64u(n.public_numbers.y.to_bytes(32, 'big'))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('csv')
    ap.add_argument('--out', default='data')
    ap.add_argument('--base', default='', help='public link of your page, used to build the edit links')
    ap.add_argument('--keys', default='keys.csv')
    ap.add_argument('--links', default='links.csv')
    ap.add_argument('--all-links', action='store_true', help='write links for every shop, not only new ones')
    a = ap.parse_args()

    keys = {}
    if os.path.exists(a.keys):
        with open(a.keys, encoding='utf-8', newline='') as f:
            for r in csv.reader(f):
                if len(r) >= 2:
                    keys[r[0]] = r[1]
    os.makedirs(a.out, exist_ok=True)
    for f in os.listdir(a.out):
        if re.match(r'^(w\d+-\d+\.json|index\.json)$', f):
            os.remove(os.path.join(a.out, f))

    seq = {}
    parts = {}
    links = []
    bad = 0
    with open(a.csv, encoding='utf-8-sig', newline='') as f:
        for line, r in enumerate(csv.DictReader(f), start=2):
            code = wilaya_code(r.get('wilaya'))
            name = txt(r.get('name'), LIM['name'])
            if not code or not name:
                bad += 1
                print('skipped line %d: missing name or unknown wilaya' % line, file=sys.stderr)
                continue
            n = seq.get(code, 0)
            seq[code] = n + 1
            sid = 'p%d_%d' % (code, n)
            new = sid not in keys
            if new:
                d, x, y = new_key()
                keys[sid] = d
            else:
                d = keys[sid]
                x, y = pub_of(d)
            off = 0
            for t in re.findall(r'[0-6]', r.get('off_days') or ''):
                off |= 1 << int(t)
            tm = lambda v, dflt: v.strip() if re.match(r'^([01]\d|2[0-3]):[0-5]\d$', (v or '').strip()) else dflt
            wa = re.sub(r'[^\d+]', '', r.get('wa') or '')
            row = [sid, name, txt(r.get('owner'), LIM['owner']), txt(r.get('phone'), LIM['phone']), txt(r.get('address'), LIM['address']),
                   txt(r.get('daira'), LIM['daira']), txt(r.get('baladiya'), LIM['baladiya']), (r.get('map') or '').strip()[:500],
                   (r.get('cat') or '').strip(), wa, KINDS.get((r.get('kind') or 'shop').strip().lower(), 1),
                   (r.get('prices') or '').replace('\r', '').strip()[:LIM['prices']], txt(r.get('note'), LIM['note']),
                   tm(r.get('open'), '08:00'), tm(r.get('close'), '20:00'), off, 1 if (r.get('paused') or '').strip() in ('1', 'true', 'yes') else 0, x, y]
            parts.setdefault((code, n // PART), []).append(row)
            if new or a.all_links:
                links.append((sid, name, r.get('phone') or '', d))

    index = {'v': 1, 'ps': PART, 'w': {}}
    total = size = 0
    for (code, p), rows in sorted(parts.items()):
        path = os.path.join(a.out, 'w%d-%d.json' % (code, p))
        data = json.dumps(rows, ensure_ascii=False, separators=(',', ':'))
        with open(path, 'w', encoding='utf-8') as f:
            f.write(data)
        size += len(data.encode('utf-8'))
        w = index['w'].setdefault(str(code), {'n': 0, 'parts': 0})
        w['n'] += len(rows)
        w['parts'] = max(w['parts'], p + 1)
        total += len(rows)
    with open(os.path.join(a.out, 'index.json'), 'w', encoding='utf-8') as f:
        json.dump(index, f, separators=(',', ':'))
    with open(a.keys, 'w', encoding='utf-8', newline='') as f:
        csv.writer(f).writerows(sorted(keys.items()))
    base = a.base.split('#')[0].split('?')[0]
    with open(a.links, 'w', encoding='utf-8-sig', newline='') as f:
        w = csv.writer(f)
        w.writerow(['id', 'name', 'phone', 'link'])
        for sid, name, phone, d in links:
            w.writerow([sid, name, phone, '%s?edit=%s&token=%s#edit.%s.%s' % (base, sid, d, sid, d) if base else ''])
    mb = size / 1048576.0
    print('%d shops in %d files, %.1f MB (skipped %d rows)' % (total, len(parts), mb, bad))
    if mb > 240:
        print('WARNING: more than ~240 MB; a published page holds at most 256 MB of files.', file=sys.stderr)
    if not base:
        print('Note: no --base given, links.csv has empty links.', file=sys.stderr)


if __name__ == '__main__':
    main()

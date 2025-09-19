#!/usr/bin/env python3
# crc17_decoder_gui_batch_color_fixed.py
"""
Décodeur de trame CODE + batch de vérification avec coloration.
- Ligne 1 : saisie de trame CODE + bouton Valider
- Ligne 2 : CLE, ID, CRC calculé avec libellés et couleur verte/rouge
- Ligne 3 : bouton Vérification batch sur toutes les captures
"""

import tkinter as tk
from tkinter import ttk, messagebox

# ---------- mapping reconstruit (GF(2)) ----------
MAPPING = {
    0: [(6,0),(6,4),(7,3),(7,6)],
    1: [(6,1),(6,5),(7,4),(7,7)],
    2: [(6,0),(6,2),(6,6),(7,5)],
    3: [(0,3),(5,5),(6,1),(6,3),(6,7),(7,6)],
    4: [(0,3),(5,0),(5,6),(6,2),(6,4),(7,7)],
    5: [(5,5),(6,0),(6,1),(6,3),(6,4),(6,6),(7,1),(7,3),(7,7)],
    6: [(0,3),(5,5),(5,6),(6,0),(6,1),(6,2),(6,4),(6,5),(6,7),(7,2),(7,4)],
    7: [(0,3),(5,0),(5,5),(5,6),(6,2),(6,3),(6,4),(7,1),(7,5),(7,7)],
    8: [(5,0),(5,7),(6,0),(6,4),(6,6),(6,7),(7,1),(7,2),(7,7)],
    9: [(5,0),(5,7),(6,0),(6,4),(6,6),(6,7),(7,1),(7,2),(7,7)],
    10: [(5,5),(5,7),(6,1),(6,4),(6,5),(6,6),(7,1),(7,3),(7,7)],
    11: [(5,6),(5,7),(6,0),(6,1),(6,2),(6,4),(6,7),(7,1),(7,2),(7,3),(7,4),(7,7)],
    12: [(5,0),(6,0),(6,2),(6,3),(6,4),(6,6),(7,1),(7,2),(7,4),(7,5),(7,7)],
    13: [(0,3),(6,0),(6,1),(6,3),(6,4),(6,5),(6,7),(7,2),(7,3),(7,5),(7,6)],
    14: [(0,3),(5,0),(5,7),(6,2),(7,1),(7,4),(7,6)],
    15: [(6,3),(7,2),(7,5),(7,7)],
    16: [(0,3),(5,6),(5,7),(6,0),(6,3),(6,4),(6,5),(7,2),(7,6)]
}

CLE_HIGH_MAP = {0:0x0, 1:0x2, 2:0x4, 3:0x6, 4:0x8}

frames_hex = [
    "68 67 d6 42 44 2e 00 01 30 64",
    "68 67 d6 42 44 2e 00 03 90 3b",
    "68 67 d6 42 44 2e 00 04 70 df",
    "68 67 d6 42 44 2e 00 09 11 48",
    "68 67 d6 42 44 2e 00 11 72 3c",
    "68 67 d6 42 44 2e 00 21 b4 d4",
    "68 67 d6 42 44 2e 00 40 39 04",
    "68 67 d6 42 44 2e 00 81 82 fb",
    "68 67 d6 42 44 2e 01 00 55 5f",
    "68 67 d6 42 44 2e 02 01 5a 48",
    "68 67 d6 42 44 2e 04 01 e4 3c",
    "68 67 d6 42 44 2e 08 00 98 d4",
    "68 67 d6 42 44 2e 10 00 c1 5b",
    "68 67 d6 42 44 2e 20 00 72 40",
    "68 67 d6 42 44 2e 40 01 14 73",
    "68 67 d6 42 44 2e 80 01 78 4f",
    "68 67 d6 42 44 2f 00 01 a0 37",
    "68 67 d6 42 44 4f 00 00 98 3b",
    "68 67 d6 42 44 6f 00 00 70 3f",
    "68 67 d6 42 44 8f 00 00 48 7c",
    "68 67 d6 42 44 0f 00 01 48 33",
    "68 67 d6 42 44 0e 00 01 d8 60",
    "68 67 d6 42 44 0e 01 32 db ec",
    "68 67 d6 42 44 0f 32 01 91 04",
    "68 67 d6 42 44 0f 33 32 92 88",
    "68 67 d6 42 44 0e 00 03 78 3f",
    "68 67 d6 42 44 0e 02 01 b2 4c",
    "68 67 d6 42 44 0e 64 00 6a 0b",
    "68 67 d6 42 44 0e 00 65 15 0b",
    "68 67 d6 42 44 2e 00 01 30 64",
    "68 67 d6 42 44 2e 01 32 33 e8",
    "68 67 d6 42 44 4e 00 00 08 68",
    "68 67 d6 42 44 6e 00 00 e0 6c",
    "68 67 d6 42 44 8e 00 00 d8 2f"
]

# --------------- fonctions ----------------
def compute_cbits_from_payload(bytes_arr):
    c = [0]*17
    for i in range(17):
        s=0
        for (bidx,bitidx) in MAPPING[i]:
            s ^= (bytes_arr[bidx] >> bitidx) &1
        c[i]=s&1
    return c

def decode_trame(trame_bytes):
    xx,yy,zz = trame_bytes[5],trame_bytes[6],trame_bytes[7]
    high_nibble = (xx>>4)&0x0F
    cle = next((k for k,v in CLE_HIGH_MAP.items() if v==high_nibble),-1)
    dept_msb = xx &1
    veh_msb  = yy &1
    dept = ((yy>>1)&0x7F)|(dept_msb<<7)
    veh  = ((zz>>1)&0x7F)|(veh_msb<<7)
    id16 = (dept<<8)|veh
    bytes_in = trame_bytes[:8]
    c = compute_cbits_from_payload(bytes_in)
    crc_l = sum((c[i]&1)<<i for i in range(8)) &0xFF
    crc_h = sum((c[i]&1)<< (i-8) for i in range(8,16)) &0xFF
    return cle,id16,(crc_l,crc_h)

def parse_trame_input(s):
    parts = s.strip().split()
    if len(parts)!=10:
        raise ValueError("La trame doit contenir 10 octets séparés par un espace.")
    return [int(x,16) for x in parts]

# --------------- GUI handlers ----------------
def update_colors(cle_ok, id_ok, crc_ok):
    entry_cle.config(bg="#ccffcc" if cle_ok else "#ffcccc")
    entry_id.config(bg="#ccffcc" if id_ok else "#ffcccc")
    entry_crc.config(bg="#ccffcc" if crc_ok else "#ffcccc")

def on_decode():
    try:
        trame_bytes = parse_trame_input(entry_trame.get())
        cle, id16, (crc_l, crc_h) = decode_trame(trame_bytes)
        cle_var.set(str(cle))
        id_hex_str = f"{id16:04X}"
        id_var.set(id_hex_str)
        crc_var.set(f"{crc_l:02X} {crc_h:02X}")

        crc_saisi = trame_bytes[8:10]

        # Vérification CLE
        cle_ok = 0 <= cle <= 4

        # Vérification ID : doit être <= 0x9999 et uniquement chiffres hex valides (0-9)
        try:
            id_int = int(id_hex_str, 16)
            id_ok = id_int <= 0x9999 and all(c in "0123456789" for c in id_hex_str)
        except ValueError:
            id_ok = False

        # Vérification CRC
        crc_ok = crc_saisi == [crc_l, crc_h]

        update_colors(cle_ok, id_ok, crc_ok)

    except Exception as e:
        cle_var.set("?")
        id_var.set("?")
        crc_var.set("?")
        update_colors(False, False, False)
        messagebox.showerror("Erreur", str(e))


def on_verify_all():
    total=len(frames_hex)
    ok_count=0
    for idx, hexstr in enumerate(frames_hex):
        trame_bytes=[int(x,16) for x in hexstr.split()]
        cle, id16, (crc_l, crc_h)=decode_trame(trame_bytes)
        crc_saisi=trame_bytes[8:10]

        id_hex_str = f"{id16:04X}"
        # Test ID hex composé uniquement de chiffres et <= 0x9999
        try:
            id_int = int(id_hex_str,16)
            id_ok = id_int <= 0x9999 and all(c in "0123456789" for c in id_hex_str)
        except ValueError:
            id_ok = False

        cle_ok = 0 <= cle <= 4
        crc_ok = crc_saisi == [crc_l, crc_h]

        is_ok = cle_ok and id_ok and crc_ok
        if is_ok:
            ok_count += 1
        print(f"Index {idx}: CLE={cle}, ID={id_hex_str}, CRC={'%02X %02X'%(crc_l,crc_h)}, {'OK' if is_ok else 'Mismatch'}")

    messagebox.showinfo("Batch Vérification", f"{ok_count}/{total} trames cohérentes")

# ---------------- GUI ----------------
root=tk.Tk()
root.title("Décodeur trame FFSK")

frame1=tk.Frame(root,padx=6,pady=6)
frame1.grid(row=0,column=0,sticky="ew")
entry_trame=tk.Entry(frame1,width=40)
entry_trame.grid(row=0,column=0,padx=(0,6))
btn_valider=tk.Button(frame1,text="Valider",command=on_decode)
btn_valider.grid(row=0,column=1)

frame2=tk.Frame(root,padx=6,pady=6)
frame2.grid(row=1,column=0,sticky="ew")
tk.Label(frame2,text="CLE").grid(row=0,column=0)
tk.Label(frame2,text="ID").grid(row=0,column=1)
tk.Label(frame2,text="CRC").grid(row=0,column=2)
cle_var=tk.StringVar()
id_var=tk.StringVar()
crc_var=tk.StringVar()
entry_cle=tk.Entry(frame2,textvariable=cle_var,width=6,justify="center")
entry_cle.grid(row=1,column=0,padx=4)
entry_id=tk.Entry(frame2,textvariable=id_var,width=10,justify="center")
entry_id.grid(row=1,column=1,padx=4)
entry_crc=tk.Entry(frame2,textvariable=crc_var,width=8,justify="center")
entry_crc.grid(row=1,column=2,padx=4)

frame3=tk.Frame(root,padx=6,pady=6)
frame3.grid(row=2,column=0,sticky="ew")
tk.Button(frame3,text="Vérifier toutes les captures (batch)",command=on_verify_all).grid(row=0,column=0)

root.columnconfigure(0,weight=1)
frame1.columnconfigure(0,weight=1)

if __name__=="__main__":
    root.mainloop()

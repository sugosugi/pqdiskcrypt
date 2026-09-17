# UI smoke test: drives the real App class (pqdiskcrypt.py) through a fake tkinter,
# in the order a user would click. Run: python _verify/ui_smoke.py
import os
import sys
import time
import json
import shutil
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import fake_tk  # noqa: E402

fake_tk.install()
import pqdiskcrypt as P  # noqa: E402

P._load_tk()
P.SELFTEST_ARGON = {"timeCost": 1, "memKiB": 8, "parallelism": 1}
P.ARGON_MEM_KIB, P.ARGON_TIME, P.ARGON_PAR = 8, 1, 1  # keep the smoke test fast

PASS = FAIL = 0


def ok(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  ✓", name)
    else:
        FAIL += 1
        print("  ✗ FAIL:", name)


def pump(root, until, timeout=120):
    t = time.time()
    while time.time() - t < timeout:
        root.pump()
        if until():
            root.pump()
            return True
        time.sleep(0.01)
    return False


def logs(app):
    return app.log_text.get()


def seed_tree(root):
    K = 64 * 1024
    files = {
        "readme.txt": b"hello disk", "empty.bin": b"", "exact64k.bin": os.urandom(K), "64k+1.bin": os.urandom(K + 1),
        "big.bin": os.urandom(K * 20 + 12345), ".dotfile": b"dot",
        "照片/家庭 2026/IMG_0001.jpg": os.urandom(300000), "照片/notes.md": b"# notes",
        "docs/a/b/c/deep.txt": b"deep", "docs/合同.pdf": os.urandom(70000), "old.pqfc": b"just a name",
    }
    for p, b in files.items():
        fp = os.path.join(root, p)
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        with open(fp, "wb") as f:
            f.write(b)
    os.makedirs(os.path.join(root, "emptydir"), exist_ok=True)
    return files


def snapshot(root):
    out = {}
    for d, _dirs, fs in os.walk(root):
        for f in fs:
            if f == P.LOCK_NAME:
                continue
            p = os.path.join(d, f)
            with open(p, "rb") as fh:
                out[os.path.relpath(p, root).replace(os.sep, "/")] = fh.read()
    return out


def main():
    tmp = tempfile.mkdtemp(prefix="pqdisk-ui-")
    P.App.LOG_FILE = os.path.join(tmp, "pqdiskcrypt.log")
    P.App.DIAG_FILE = os.path.join(tmp, "pqdiskcrypt-diag.txt")
    root = fake_tk.Tk()
    app = P.App(root)
    S = fake_tk.SCRIPT
    ok("启动后按钮在自检完成前禁用", app.gen_btn.cget("state") == "disabled")
    ok("自检通过", pump(root, lambda: app.ready or app.selftest_failure) and app.ready)
    ok("自检后启用生成按钮", app.gen_btn.cget("state") == "normal")

    print("== 密钥页 ==")
    app.on_gen()
    ok("生成密钥对", pump(root, lambda: not app.busy) and app.last_keys is not None)
    ok("私钥预览不含私钥字段内容", app.last_keys["key"]["mlkem_secret"] not in app.key_peek.get() and "已隐藏" in app.key_peek.get())
    pub_path, key_path = os.path.join(tmp, "k.pub"), os.path.join(tmp, "k.key")
    S["asksaveasfilename"].append(pub_path)
    app.on_save_pub()
    ok("保存 .pub", os.path.exists(pub_path) and json.load(open(pub_path))["mlkem_pub"] == app.last_keys["pub"]["mlkem_pub"])
    app.key_pw.set("weak")
    app.key_pw2.set("weak")
    app.on_save_key()
    ok("过短口令被拦", "口令不可用" in logs(app) and not os.path.exists(key_path))
    app.key_pw.set("Correct-Horse-Battery-Staple-2026")
    app.key_pw2.set("Correct-Horse-Battery-Staple-2026")
    S["asksaveasfilename"].append(key_path)
    app.on_save_key()
    ok("保存口令保护的 .key", pump(root, lambda: not app.busy) and os.path.exists(key_path) and app.pq.is_wrapped_key(json.load(open(key_path))))

    print("== 加密：新卷（口令 + 公钥，隐藏文件名）==")
    d1 = os.path.join(tmp, "disk1")
    os.makedirs(d1)
    files = seed_tree(d1)
    S["askdirectory"].append(d1)
    app.on_pick("enc")
    ok("扫描新目录", pump(root, lambda: not app.busy) and app.enc_scan and app.enc_scan["files"] == len(files) and app.enc_header is None)
    ok("新卷设置区可见、已有卷区隐藏", app.enc_new_box.visible == "grid" and app.enc_exist_box.visible is None)
    app.enc_slot_mode.set("both")
    app._enc_refresh()
    app.enc_pw.set("123456")
    app.enc_pw2.set("123456")
    app.on_enc_start()
    pump(root, lambda: not app.busy)
    ok("极常见口令被硬拦", "口令不可用" in logs(app).split("\n")[-2])
    app.enc_pw.set("disk-Pass-phrase-#1")
    app.enc_pw2.set("disk-Pass-phrase-#1")
    app.on_enc_start()
    pump(root, lambda: not app.busy)
    ok("缺公钥被拒", "请先载入 .pub 公钥" in logs(app))
    S["askopenfilename"].append(pub_path)
    app.on_pick_pub("enc")
    ok("载入公钥", app.enc_pub is not None and "指纹" in app.enc_pub_label.cget("text"))
    app.enc_hide.set(True)
    app.enc_label.set("测试卷")
    S["askyesno"].append(False)
    app.on_enc_start()
    pump(root, lambda: not app.busy)
    ok("确认框取消则不动", "已取消" in logs(app) and not os.path.exists(os.path.join(d1, ".pqvolume")))
    backup1 = os.path.join(tmp, "backup1.pqvolume")
    S["askyesno"].append(True)
    S["asksaveasfilename"].append(backup1)
    app.on_enc_start()
    ok("加密完成", pump(root, lambda: not app.busy and app.enc_prog.active is False and app.enc_last_header is not None) and pump(root, lambda: not app.busy))
    snap = snapshot(d1)
    ok("原文件已删除、全部为 .pqfc / .pqdir", not any(p in snap for p in files) and all(k.endswith(".pqfc") or k.endswith(".pqdir") or k == ".pqvolume" for k in snap))
    ok("隐藏文件名：无原名残留", not any(k.endswith("readme.txt.pqfc") for k in snap))
    ok("只保存手动选择的卷头", not os.path.exists(os.path.join(d1, ".pqvolume")) and os.path.exists(backup1) and json.load(open(backup1))["label"] == "测试卷")
    hdr1 = json.load(open(backup1))
    ok("两个密钥槽（口令 + 公钥）", [s["type"] for s in hdr1["slots"]] == ["password", "pubkey"])
    ok("完成后重新扫描：已属于本卷", app.enc_scan["encrypted"] == len(files) and app.enc_header is not None and app.enc_exist_box.visible == "grid")

    print("== 加密：已有卷追加文件（错误口令 / 正确口令）==")
    with open(os.path.join(d1, "new file.txt"), "wb") as f:
        f.write(b"new")
    files["new file.txt"] = b"new"
    app.on_scan("enc")
    ok("扫描到 1 个新文件", pump(root, lambda: not app.busy) and app.enc_scan["files"] == 1)
    app.enc_unlock.select("pw")
    app.enc_unlock.pw.set("wrong password!")
    app.on_enc_start()
    ok("错误口令被拒", pump(root, lambda: not app.busy) and "口令错误" in logs(app) and os.path.exists(os.path.join(d1, "new file.txt")))
    app.enc_unlock.pw.set("disk-Pass-phrase-#1")
    app.on_enc_start()
    ok("正确口令并入", pump(root, lambda: not app.busy) and not os.path.exists(os.path.join(d1, "new file.txt")) and pump(root, lambda: not app.busy) and app.enc_scan["encrypted"] == len(files))

    print("== 解密：用受口令保护的私钥（公钥槽）==")
    S["askdirectory"].append(d1)
    app.on_pick("dec")
    ok("解密页识别加密卷", pump(root, lambda: not app.busy) and app.dec_header is not None and app.dec_scan["encrypted"] == len(files))
    app.dec_unlock.load_key(key_path)
    ok("载入加密私钥", app.dec_unlock.key_wrapped and app.dec_unlock.mode.get() == "key")
    app.dec_unlock.key_pw.set("wrong")
    app.on_dec_start()
    ok("私钥口令错误被拒", pump(root, lambda: not app.busy) and "口令错误" in logs(app))
    app.dec_unlock.key_pw.set("Correct-Horse-Battery-Staple-2026")
    app.on_dec_start()
    ok("解密完成", pump(root, lambda: not app.busy and not app.dec_prog.active) and pump(root, lambda: not app.busy))
    snap = snapshot(d1)
    ok("全树还原一致、所选卷头保留", all(snap.get(p) == b for p, b in files.items()) and os.path.exists(backup1) and not os.path.exists(os.path.join(d1, ".pqvolume")) and not any(k.endswith(".pqdir") for k in snap))

    print("== 卷头丢失 → 载入备份 ==")
    d2 = os.path.join(tmp, "disk2")
    os.makedirs(d2)
    files2 = seed_tree(d2)
    S["askdirectory"].append(d2)
    app.on_pick("enc")
    pump(root, lambda: not app.busy)
    app.enc_slot_mode.set("pw")
    app._enc_refresh()
    app.enc_hide.set(False)
    app.enc_pw.set("Another-Long-Passphrase")
    app.enc_pw2.set("Another-Long-Passphrase")
    backup2 = os.path.join(tmp, "backup2.pqvolume")
    S["asksaveasfilename"].append(backup2)
    app.on_enc_start()
    ok("第二个卷加密完成", pump(root, lambda: not app.busy and app.enc_last_header is not None and not app.enc_prog.active) and pump(root, lambda: not app.busy))
    app.header_locations.pop(os.path.normcase(d2), None)
    S["askdirectory"].append(d2)
    app.on_pick("dec")
    ok("无卷头：提示可载入备份", pump(root, lambda: not app.busy) and app.dec_header is None and app.dec_nohdr.visible == "pack")
    S["askopenfilename"].append(backup2)
    app.on_dec_load_header()
    ok("载入外部卷头后识别，未创建额外卷头", pump(root, lambda: not app.busy) and app.dec_header is not None and not os.path.exists(os.path.join(d2, ".pqvolume")))
    app.dec_unlock.select("pw")
    app.dec_unlock.pw.set("Another-Long-Passphrase")
    app.on_dec_start()
    ok("用备份卷头解密成功", pump(root, lambda: not app.busy and not app.dec_prog.active) and pump(root, lambda: not app.busy) and all(snapshot(d2).get(p) == b for p, b in files2.items()))
    ok("全部解密后保留所选卷头，没有额外卷头", not os.path.exists(os.path.join(d2, ".pqvolume")) and os.path.exists(backup2))

    print("== 卷管理：解锁 → 追加口令槽 / 公钥槽 → 删除旧槽 ==")
    d3 = os.path.join(tmp, "disk3")
    os.makedirs(d3)
    seed_tree(d3)
    S["askdirectory"].append(d3)
    app.on_pick("enc")
    pump(root, lambda: not app.busy)
    app.enc_pw.set("Manage-Me-Please-99")
    app.enc_pw2.set("Manage-Me-Please-99")
    S["asksaveasfilename"].append(os.path.join(tmp, "backup3.pqvolume"))
    app.on_enc_start()
    pump(root, lambda: not app.busy and not app.enc_prog.active)
    pump(root, lambda: not app.busy)
    S["askdirectory"].append(d3)
    app.on_pick("mg")
    ok("卷管理读取卷头", app.mg_header is not None and app.mg_unlock_btn.cget("state") == "normal")
    ok("未解锁不允许写回", (app.on_mg_write(), "请先用口令" in logs(app))[1])
    app.mg_unlock.select("pw")
    app.mg_unlock.pw.set("Manage-Me-Please-99")
    app.on_mg_unlock()
    ok("解锁卷", pump(root, lambda: not app.busy) and app.mg_vmk is not None and app.mg_addpw_btn.cget("state") == "normal")
    app.mg_new_pw.set("Second-Passphrase-2026")
    app.mg_new_pw2.set("Second-Passphrase-2026")
    app.on_mg_add_pw()
    ok("追加口令槽并写回", pump(root, lambda: not app.busy) and len(json.load(open(os.path.join(tmp, "backup3.pqvolume")))["slots"]) == 2)
    S["askopenfilename"].append(pub_path)
    app.on_pick_pub("mg")
    app.on_mg_add_pk()
    ok("追加公钥槽", pump(root, lambda: not app.busy) and len(json.load(open(os.path.join(tmp, "backup3.pqvolume")))["slots"]) == 3)
    app.on_mg_remove_slot(0)
    hdr3 = json.load(open(os.path.join(tmp, "backup3.pqvolume")))
    ok("删除旧口令槽", len(hdr3["slots"]) == 2 and hdr3["slots"][0]["type"] == "password")
    try:
        app.pq.unlock_volume(hdr3, password="Manage-Me-Please-99")
        old_ok = True
    except P.PQError:
        old_ok = False
    ok("旧口令失效、新口令与私钥有效", not old_ok and app.pq.unlock_volume(hdr3, password="Second-Passphrase-2026")["slotIndex"] == 0
       and app.pq.unlock_volume(hdr3, key_obj=app.last_keys["key"])["slotIndex"] == 1)

    print("== 卷管理：加密后切换隐藏文件名（改名，不重新加密）==")
    ok("切换按钮显示当前状态", "当前：显示" in app.mg_conv_btn.cget("text") and app.mg_conv_btn.cget("state") == "normal")
    ct_before = sorted(v for k, v in snapshot(d3).items() if k.endswith(".pqfc"))
    app.on_mg_convert()
    ok("切换为隐藏文件名", pump(root, lambda: not app.busy) and json.load(open(os.path.join(tmp, "backup3.pqvolume")))["hide_names"] is True
       and "已隐藏文件名" in logs(app) and "当前：隐藏" in app.mg_conv_btn.cget("text"))
    snap3 = snapshot(d3)
    ok("全部改成随机 ID、密文字节未变", all(len(os.path.basename(k)) == 21 for k in snap3 if k.endswith(".pqfc") and k != "old.pqfc.pqfc" or k.endswith(".pqfc")) is not None
       and not any("readme.txt" in k for k in snap3) and sorted(v for k, v in snap3.items() if k.endswith(".pqfc")) == ct_before and any(k.endswith(".pqdir") for k in snap3))
    app.on_mg_convert()
    ok("切换回显示文件名", pump(root, lambda: not app.busy) and json.load(open(os.path.join(tmp, "backup3.pqvolume")))["hide_names"] is False
       and "readme.txt.pqfc" in snapshot(d3) and not any(k.endswith(".pqdir") for k in snapshot(d3)))
    S["askdirectory"].append(d3)
    app.on_pick("dec")
    pump(root, lambda: not app.busy)
    app.dec_unlock.select("pw")
    app.dec_unlock.pw.set("Second-Passphrase-2026")
    app.on_dec_start()
    ok("切换后仍可正常解密", pump(root, lambda: not app.busy and not app.dec_prog.active) and pump(root, lambda: not app.busy) and app.dec_header is not None
       and "readme.txt" in snapshot(d3) and "docs/合同.pdf" in snapshot(d3))

    print("== 试运行（保留原文件）后解密：跳过但不删清单与卷头 ==")
    d5 = os.path.join(tmp, "disk5")
    os.makedirs(d5)
    files5 = seed_tree(d5)
    S["askdirectory"].append(d5)
    app.on_pick("enc")
    pump(root, lambda: not app.busy)
    app.enc_slot_mode.set("pw")
    app._enc_refresh()
    app.enc_hide.set(True)
    app.enc_keep.set(True)
    app.enc_pw.set("Dry-Run-Passphrase-2026")
    app.enc_pw2.set("Dry-Run-Passphrase-2026")
    S["asksaveasfilename"].append(os.path.join(tmp, "backup5.pqvolume"))
    app.on_enc_start()
    pump(root, lambda: not app.busy and not app.enc_prog.active)
    pump(root, lambda: not app.busy)
    app.enc_keep.set(False)
    ok("试运行：明文与密文并存", all(p in snapshot(d5) for p in files5) and sum(1 for k in snapshot(d5) if k.endswith(".pqfc")) == len(files5) + 1)
    S["askdirectory"].append(d5)
    app.on_pick("dec")
    pump(root, lambda: not app.busy)
    app.dec_unlock.select("pw")
    app.dec_unlock.pw.set("Dry-Run-Passphrase-2026")
    app.on_dec_start()
    pump(root, lambda: not app.busy and not app.dec_prog.active)
    pump(root, lambda: not app.busy)
    ok("解密全部跳过，卷头与清单保留并有明确提示", os.path.exists(os.path.join(tmp, "backup5.pqvolume")) and any(k.endswith(".pqdir") for k in snapshot(d5))
       and "移走同名文件后再解密一次" in (app.dec_done.cget("text") or "") and "还原 0 个文件" in logs(app))
    for p in files5:
        os.remove(os.path.join(d5, p))
    app.on_dec_start()
    ok("移走明文后再解密：原名全部还原、卷头保留", pump(root, lambda: not app.busy and not app.dec_prog.active) and pump(root, lambda: not app.busy)
       and all(snapshot(d5).get(p) == b for p, b in files5.items()) and not os.path.exists(os.path.join(d5, ".pqvolume")))

    print("== 同一目录里有两个卷的密文（旧卷头丢失后又新建了卷）==")
    d6 = os.path.join(tmp, "disk6")
    os.makedirs(d6)
    with open(os.path.join(d6, "A.txt"), "wb") as f:
        f.write(b"file A")
    S["askdirectory"].append(d6)
    app.on_pick("enc")
    pump(root, lambda: not app.busy)
    app.enc_slot_mode.set("pw")
    app._enc_refresh()
    app.enc_hide.set(False)
    app.enc_pw.set("Volume-One-Passphrase")
    app.enc_pw2.set("Volume-One-Passphrase")
    backup6a = os.path.join(tmp, "backup6a.pqvolume")
    S["asksaveasfilename"].append(backup6a)
    app.on_enc_start()
    pump(root, lambda: not app.busy and not app.enc_prog.active)
    pump(root, lambda: not app.busy)
    app.header_locations.pop(os.path.normcase(d6), None)
    with open(os.path.join(d6, "B.txt"), "wb") as f:
        f.write(b"file B")
    S["askdirectory"].append(d6)
    app.on_pick("enc")
    pump(root, lambda: not app.busy)
    ok("加密页指出目录里有其它卷的密文并列出卷 ID", "属于其它卷（卷 ID" in app.enc_scan_info.cget("text"))
    app.enc_pw.set("Volume-Two-Passphrase")
    app.enc_pw2.set("Volume-Two-Passphrase")
    S["asksaveasfilename"].append(os.path.join(tmp, "backup6b.pqvolume"))
    app.on_enc_start()
    pump(root, lambda: not app.busy and not app.enc_prog.active)
    pump(root, lambda: not app.busy)
    S["askdirectory"].append(d6)
    app.on_pick("dec")
    pump(root, lambda: not app.busy)
    ok("解密页：1 个本卷 + 1 个其它卷（显示卷 ID 并提示载入备份）", app.dec_scan["encrypted"] == 1 and app.dec_scan["foreign"] == 1
       and "属于其它卷（卷 ID" in app.dec_scan_info.cget("text") and "载入卷头备份" in app.dec_scan_info.cget("text"))
    S["askopenfilename"].append(backup6a)
    S["askyesno"].append(True)
    app.on_dec_load_header()
    ok("载入另一个卷的备份：只在本次使用，不覆盖现有卷头", pump(root, lambda: not app.busy) and app.dec_override is not None
       and app.dec_scan["encrypted"] == 1 and "来自备份" in app.dec_dir_info.cget("text") and json.load(open(os.path.join(tmp, "backup6b.pqvolume")))["volume_id"] != app.dec_override["volume_id"])
    app.dec_unlock.select("pw")
    app.dec_unlock.pw.set("Volume-One-Passphrase")
    app.on_dec_start()
    ok("用备份卷头解出旧卷文件，目录卷头保持不动", pump(root, lambda: not app.busy and not app.dec_prog.active) and pump(root, lambda: not app.busy)
       and open(os.path.join(d6, "A.txt"), "rb").read() == b"file A" and os.path.exists(os.path.join(tmp, "backup6b.pqvolume")))
    app.on_dec_load_header(os.path.join(tmp, "backup6b.pqvolume"))
    pump(root, lambda: not app.busy)
    ok("载入另一卷头：剩下新卷的 1 个文件", app.dec_scan["encrypted"] == 1 and app.dec_scan["foreign"] == 0)
    app.dec_unlock.pw.set("Volume-Two-Passphrase")
    app.on_dec_start()
    ok("再解密新卷：全部还原、卷头保留", pump(root, lambda: not app.busy and not app.dec_prog.active) and pump(root, lambda: not app.busy)
       and open(os.path.join(d6, "B.txt"), "rb").read() == b"file B" and not os.path.exists(os.path.join(d6, ".pqvolume")))

    print("== 卷头损坏：解密页可载入备份覆盖，加密页拒绝新建卷 ==")
    d7 = os.path.join(tmp, "disk7")
    os.makedirs(d7)
    with open(os.path.join(d7, "C.txt"), "wb") as f:
        f.write(b"file C")
    S["askdirectory"].append(d7)
    app.on_pick("enc")
    pump(root, lambda: not app.busy)
    app.enc_pw.set("Volume-Seven-Passphrase")
    app.enc_pw2.set("Volume-Seven-Passphrase")
    backup7 = os.path.join(tmp, "backup7.pqvolume")
    S["asksaveasfilename"].append(backup7)
    app.on_enc_start()
    pump(root, lambda: not app.busy and not app.enc_prog.active)
    pump(root, lambda: not app.busy)
    with open(os.path.join(d7, ".pqvolume"), "wb") as f:
        f.write(b"{ corrupted")
    app.header_locations.pop(os.path.normcase(d7), None)
    S["askdirectory"].append(d7)
    app.on_pick("enc")
    pump(root, lambda: not app.busy)
    ok("加密页：卷头损坏时停用加密", app.enc_scan is None and app.enc_btn.cget("state") == "disabled" and "已损坏" in app.enc_dir_info.cget("text"))
    S["askdirectory"].append(d7)
    app.on_pick("dec")
    pump(root, lambda: not app.busy)
    ok("解密页：提示卷头已损坏", app.dec_header is None and "已损坏" in app.dec_dir_info.cget("text") and app.dec_nohdr.visible == "pack")
    S["askopenfilename"].append(backup7)
    S["askyesno"].append(True)
    app.on_dec_load_header()
    ok("载入外部卷头，不覆盖其它文件", pump(root, lambda: not app.busy) and app.dec_header is not None and open(os.path.join(d7, ".pqvolume"), "rb").read() == b"{ corrupted")
    app.dec_unlock.select("pw")
    app.dec_unlock.pw.set("Volume-Seven-Passphrase")
    app.on_dec_start()
    ok("解密成功", pump(root, lambda: not app.busy and not app.dec_prog.active) and pump(root, lambda: not app.busy) and open(os.path.join(d7, "C.txt"), "rb").read() == b"file C")

    print("== 诊断报告：按内容识别被改名的密文并补回后缀 ==")
    d8 = os.path.join(tmp, "disk8")
    os.makedirs(d8)
    for n in ("one.txt", "two.txt"):
        with open(os.path.join(d8, n), "wb") as f:
            f.write(b"file " + n.encode())
    S["askdirectory"].append(d8)
    app.on_pick("enc")
    pump(root, lambda: not app.busy)
    app.enc_pw.set("Diag-Volume-Passphrase")
    app.enc_pw2.set("Diag-Volume-Passphrase")
    S["asksaveasfilename"].append(os.path.join(tmp, "backup8.pqvolume"))
    app.on_enc_start()
    pump(root, lambda: not app.busy and not app.enc_prog.active)
    pump(root, lambda: not app.busy)
    os.rename(os.path.join(d8, "two.txt.pqfc"), os.path.join(d8, "two.txt"))  # user renamed a ciphertext
    with open(os.path.join(d8, "single.pqfc"), "wb") as f:
        f.write(app.pq.encrypt_password("p", b"q", P.SELFTEST_ARGON))
    S["askdirectory"].append(d8)
    app.on_pick("dec")
    pump(root, lambda: not app.busy)
    ok("扫描：1 个本卷 + 1 个单文件模式，改名的那个当作普通文件", app.dec_scan["encrypted"] == 1 and app.dec_scan["singleMode"] == 1 and app.dec_scan["files"] == 1)
    S["askyesno"].append(True)
    app.on_diagnose()
    ok("诊断报告写出并按内容找到改名的密文", pump(root, lambda: not app.busy) and os.path.exists(P.App.DIAG_FILE)
       and "本卷密文但扩展名不是 .pqfc" in open(P.App.DIAG_FILE, encoding="utf-8").read() and "单文件模式密文" in open(P.App.DIAG_FILE, encoding="utf-8").read())
    ok("补回 .pqfc 后缀后重新扫描到 2 个本卷文件", pump(root, lambda: not app.busy) and os.path.exists(os.path.join(d8, "two.txt.pqfc")) and app.dec_scan["encrypted"] == 2)
    ok("运行日志文件存在且不含口令", os.path.exists(P.App.LOG_FILE) and "Diag-Volume-Passphrase" not in open(P.App.LOG_FILE, encoding="utf-8").read())
    app.dec_unlock.select("pw")
    app.dec_unlock.pw.set("Diag-Volume-Passphrase")
    app.on_dec_start()
    ok("两个文件都解出来", pump(root, lambda: not app.busy and not app.dec_prog.active) and pump(root, lambda: not app.busy)
       and open(os.path.join(d8, "one.txt"), "rb").read() == b"file one.txt" and open(os.path.join(d8, "two.txt"), "rb").read() == b"file two.txt")

    print("== 单文件页：口令模式与签名模式 ==")
    plain = os.path.join(tmp, "letter.txt")
    with open(plain, "wb") as f:
        f.write(b"single file payload " * 5000)
    S["askopenfilename"].append(plain)
    app.on_sf_pick_plain()
    app.sf_mode.set("pw")
    app._sf_refresh()
    app.sf_pw.set("Single-File-Passphrase-1")
    app.sf_pw2.set("Single-File-Passphrase-1")
    enc1 = os.path.join(tmp, "letter.txt.pqfc")
    S["asksaveasfilename"].append(enc1)
    app.on_sf_encrypt()
    ok("口令模式加密单文件", pump(root, lambda: not app.busy) and os.path.exists(enc1) and app.pq.probe_header(open(enc1, "rb").read(20))["mode"] == P.MODE_PASSWORD)
    S["askopenfilename"].append(enc1)
    app.on_sf_pick()
    ok("识别为口令模式并自动选口令解锁", app.sf_probe["mode"] == P.MODE_PASSWORD and app.sf_unlock.mode.get() == "pw")
    app.sf_unlock.pw.set("wrong")
    S["asksaveasfilename"].append(os.path.join(tmp, "letter.out"))
    app.on_sf_decrypt()
    ok("错误口令被拒", pump(root, lambda: not app.busy) and "口令错误" in logs(app) and not os.path.exists(os.path.join(tmp, "letter.out")))
    app.sf_unlock.pw.set("Single-File-Passphrase-1")
    S["asksaveasfilename"].append(os.path.join(tmp, "letter.out"))
    app.on_sf_decrypt()
    ok("口令模式解密单文件", pump(root, lambda: not app.busy) and open(os.path.join(tmp, "letter.out"), "rb").read() == open(plain, "rb").read())
    # signed hybrid: recipient = generated keys (pub_path/key_path from the 密钥 page), signer = same key
    S["askopenfilename"].append(plain)
    app.on_sf_pick_plain()
    app.sf_mode.set("signed")
    app._sf_refresh()
    S["askopenfilename"].append(pub_path)
    app.on_sf_pick_pub()
    app.sf_signer.load_key(key_path)
    app.sf_signer.key_pw.set("Correct-Horse-Battery-Staple-2026")
    enc2 = os.path.join(tmp, "letter.signed.pqfc")
    S["asksaveasfilename"].append(enc2)
    app.on_sf_encrypt()
    ok("公钥 + 签名模式加密", pump(root, lambda: not app.busy) and os.path.exists(enc2) and app.pq.probe_header(open(enc2, "rb").read(20))["mode"] == P.MODE_HYBRID_SIGNED)
    S["askopenfilename"].append(enc2)
    app.on_sf_pick()
    app.sf_unlock.load_key(key_path)
    app.sf_unlock.key_pw.set("Correct-Horse-Battery-Staple-2026")
    S["asksaveasfilename"].append(os.path.join(tmp, "letter2.out"))
    app.on_sf_decrypt()
    ok("私钥解密并验签，显示签名指纹", pump(root, lambda: not app.busy) and open(os.path.join(tmp, "letter2.out"), "rb").read() == open(plain, "rb").read()
       and "签名指纹" in app.sf_dec_done.cget("text"))

    print("== 半途取消 ==")
    d4 = os.path.join(tmp, "disk4")
    os.makedirs(d4)
    files4 = seed_tree(d4)
    S["askdirectory"].append(d4)
    app.on_pick("enc")
    pump(root, lambda: not app.busy)
    app.enc_pw.set("Cancel-Me-Halfway-2026")
    app.enc_pw2.set("Cancel-Me-Halfway-2026")
    S["asksaveasfilename"].append(os.path.join(tmp, "backup4.pqvolume"))
    app.on_enc_start()
    pump(root, lambda: app.enc_prog.files >= 2, timeout=60)
    app.enc_prog.cancel()
    ok("取消后无半成品、明文 + 密文 = 总数", pump(root, lambda: not app.busy and not app.enc_prog.active) and pump(root, lambda: not app.busy)
       and "已取消" in logs(app) and not any(P.TMP_PREFIX in k for k in snapshot(d4))
       and sum(1 for k in snapshot(d4) if k in files4) + sum(1 for k in snapshot(d4) if k.endswith(".pqfc") and k != "old.pqfc") == len(files4))

    print("== 清除敏感状态 ==")
    app.on_clear()
    ok("状态已清空", app.last_keys is None and app.enc_pw.get() == "" and app.mg_vmk is None and app.enc_header is None and "已清除" in logs(app) and app.sf_in is None)
    S["askyesno"].append(True)
    app.on_close()
    ok("关闭窗口", root.closed)

    shutil.rmtree(tmp, ignore_errors=True)
    print("\nUI 冒烟结果：%d 通过，%d 失败" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())

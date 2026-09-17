# Minimal in-memory stand-in for tkinter / ttk / filedialog / messagebox.
# Only what pqdiskcrypt.py uses; dialogs return scripted answers.
import sys
import types
import threading


class TclError(Exception):
    pass


class _Var:
    def __init__(self, master=None, value=None, name=None):
        self._v = value if value is not None else self._default()
        self._traces = []

    def _default(self):
        return ""

    def get(self):
        return self._v

    def set(self, v):
        self._v = v
        for cb in list(self._traces):
            cb()

    def trace_add(self, mode, cb):
        self._traces.append(lambda: cb(None, None, mode))
        return "trace"


class StringVar(_Var):
    pass


class BooleanVar(_Var):
    def _default(self):
        return False

    def get(self):
        return bool(self._v)


class IntVar(_Var):
    def _default(self):
        return 0


class Widget:
    def __init__(self, master=None, **kw):
        self.master = master
        self.kw = dict(kw)
        self.children = []
        self.visible = None
        self.destroyed = False
        self._text_content = ""
        if master is not None and hasattr(master, "children"):
            master.children.append(self)

    # geometry
    def pack(self, **kw):
        self.visible = "pack"
        return self

    def grid(self, **kw):
        self.visible = "grid"
        return self

    def place(self, **kw):
        self.visible = "place"

    def pack_forget(self):
        self.visible = None

    def grid_forget(self):
        self.visible = None

    def grid_remove(self):
        self.visible = None

    def columnconfigure(self, *a, **k):
        pass

    def rowconfigure(self, *a, **k):
        pass

    # config
    def configure(self, cnf=None, **kw):
        if cnf:
            kw.update(cnf)
        self.kw.update(kw)

    config = configure

    def cget(self, key):
        return self.kw.get(key)

    def __getitem__(self, key):
        return self.kw.get(key)

    def state(self, *a):
        return []

    def bind(self, *a, **k):
        pass

    def bind_all(self, *a, **k):
        pass

    def unbind_all(self, *a, **k):
        pass

    def focus_set(self):
        pass

    def winfo_children(self):
        return [c for c in self.children if not c.destroyed]

    def destroy(self):
        self.destroyed = True
        if self.master is not None and hasattr(self.master, "children") and self in self.master.children:
            self.master.children.remove(self)

    def after(self, ms, fn=None, *args):
        return _root().after(ms, fn, *args)

    def invoke(self):
        cmd = self.kw.get("command")
        if cmd:
            return cmd()

    # Text-like
    def insert(self, index, text, *tags):
        if index in ("end", "insert"):
            self._text_content += text
        else:
            self._text_content = text + self._text_content if index == "1.0" else self._text_content + text

    def delete(self, a=None, b=None):
        if a == "1.0" and b == "end":
            self._text_content = ""
        elif a == "1.0" and b == "2.0":
            i = self._text_content.find("\n")
            self._text_content = self._text_content[i + 1:] if i >= 0 else ""
        else:
            self._text_content = ""

    def get(self, a=None, b=None):
        return self._text_content

    def see(self, index):
        pass

    def tag_configure(self, *a, **k):
        pass

    # Canvas-like
    def create_window(self, *a, **k):
        return 1

    def itemconfigure(self, *a, **k):
        pass

    def bbox(self, *a):
        return (0, 0, 100, 100)

    def yview(self, *a):
        pass

    def yview_scroll(self, *a):
        pass

    def set(self, *a):
        pass

    # Notebook / PanedWindow
    def add(self, child, **kw):
        pass


class Tk(Widget):
    _instance = None

    def __init__(self):
        super().__init__(None)
        Tk._instance = self
        self.timers = []
        self._lock = threading.Lock()
        self.closed = False

    def title(self, *a):
        pass

    def geometry(self, *a):
        pass

    def minsize(self, *a):
        pass

    def protocol(self, name, fn):
        self.kw["protocol:" + name] = fn

    def after(self, ms, fn=None, *args):
        with self._lock:
            self.timers.append((fn, args))
        return "after"

    def pump(self):
        with self._lock:
            due, self.timers = self.timers, []
        for fn, args in due:
            if fn:
                fn(*args)
        return len(due)

    def mainloop(self):
        pass

    def destroy(self):
        self.closed = True


def _root():
    return Tk._instance


class Canvas(Widget):
    pass


class Text(Widget):
    pass


# ---- ttk ---------------------------------------------------------------
ttk = types.ModuleType("tkinter.ttk")
for _name in ("Frame", "Label", "Button", "Entry", "Checkbutton", "Radiobutton", "LabelFrame", "Notebook",
              "Progressbar", "Scrollbar", "PanedWindow", "Separator", "Combobox"):
    setattr(ttk, _name, type(_name, (Widget,), {}))


class Style:
    def theme_use(self, *a):
        pass


ttk.Style = Style

# ---- dialogs (scripted) ------------------------------------------------
filedialog = types.ModuleType("tkinter.filedialog")
messagebox = types.ModuleType("tkinter.messagebox")
SCRIPT = {"askdirectory": [], "askopenfilename": [], "asksaveasfilename": [], "askyesno": [], "showinfo": []}
CALLS = []


def _scripted(name, default):
    def fn(*a, **k):
        CALLS.append((name, k.get("title") or k.get("initialfile") or ""))
        if SCRIPT[name]:
            v = SCRIPT[name].pop(0)
            return v() if callable(v) else v
        return default
    return fn


filedialog.askdirectory = _scripted("askdirectory", "")
filedialog.askopenfilename = _scripted("askopenfilename", "")
filedialog.asksaveasfilename = _scripted("asksaveasfilename", "")
messagebox.askyesno = _scripted("askyesno", True)
messagebox.askokcancel = _scripted("askyesno", True)
messagebox.showinfo = _scripted("showinfo", None)
messagebox.showerror = _scripted("showinfo", None)
messagebox.showwarning = _scripted("showinfo", None)


def install():
    mod = sys.modules[__name__]
    tkmod = types.ModuleType("tkinter")
    for k in ("Tk", "Canvas", "Text", "StringVar", "BooleanVar", "IntVar", "TclError", "Widget"):
        setattr(tkmod, k, getattr(mod, k))
    tkmod.ttk = ttk
    tkmod.filedialog = filedialog
    tkmod.messagebox = messagebox
    sys.modules["tkinter"] = tkmod
    sys.modules["tkinter.ttk"] = ttk
    sys.modules["tkinter.filedialog"] = filedialog
    sys.modules["tkinter.messagebox"] = messagebox
    return tkmod

"""Interfaz grafica de KDSPN-64 (Tkinter).

Es una capa fina: no contiene nada del algoritmo. Cada boton ejecuta el programa
de linea de comandos `ciber` con subprocess y muestra lo que devuelve. Si `ciber`
termina con un codigo distinto de 0, se muestra su mensaje de error (stderr).

Uso:  python ciber_gui.py
La ruta de ciber.exe se puede cambiar en el campo de arriba.

Es un cifrado de juguete para aprender: no es seguro.
"""

import os
import subprocess
import tempfile
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

MAX_TEXT_BYTES = 100  # mismo limite que MAX_TEXT_BYTES en Config.h

# Carpetas de compilacion donde se busca ciber.exe, relativas a la raiz del proyecto (ciber/)
BUILD_DIRS = ["cmake-build-debug", "cmake-build-release", "cmake-build-claude"]
EXE_NAME = "ciber.exe" if os.name == "nt" else "ciber"


def default_exe_path():
    """Ruta por defecto de ciber: el compilado mas reciente de las carpetas de compilacion.

    Se toma el mas reciente (y no el primero que exista) para no usar por error
    un ciber.exe viejo que haya quedado de antes de la linea de comandos.
    """
    here = os.path.dirname(os.path.abspath(__file__))       # .../ciber/CypherAlgorithm/gui
    project = os.path.dirname(os.path.dirname(here))        # .../ciber
    candidates = [os.path.join(project, d, EXE_NAME) for d in BUILD_DIRS]
    existing = [p for p in candidates if os.path.isfile(p)]
    if existing:
        return max(existing, key=os.path.getmtime)
    return candidates[0]


def run_ciber(exe, args):
    """Ejecuta ciber con los argumentos dados.

    Devuelve (ok, stdout, stderr). Nunca lanza excepcion: si el programa no
    existe o no se puede ejecutar, ok es False y stderr explica por que.
    """
    if not os.path.isfile(exe):
        return False, "", "No se encontro el programa ciber en:\n%s\n\nCompilalo o corrige la ruta." % exe
    try:
        # CREATE_NO_WINDOW evita que se abra una consola negra en cada clic (solo Windows).
        # Se ejecuta desde la carpeta temporal: los comandos de texto no usan archivos,
        # y asi ningun programa equivocado puede tocar archivos de la carpeta del proyecto.
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        proc = subprocess.run([exe] + list(args), capture_output=True, timeout=30,
                              creationflags=flags, cwd=tempfile.gettempdir())
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, "", "No se pudo ejecutar ciber: %s" % e
    # ciber escribe UTF-8 en modo binario; quitamos solo el salto de linea final que agrega
    out = proc.stdout.decode("utf-8", errors="replace")
    if out.endswith("\n"):
        out = out[:-1]
    err = proc.stderr.decode("utf-8", errors="replace").strip()
    return proc.returncode == 0, out, err


def text_bytes(text):
    """Bytes que ocupa el texto en UTF-8 (una letra con acento ocupa 2)."""
    return len(text.encode("utf-8"))


def encrypt_text(exe, text, key):
    """Cifra un texto. Devuelve (ok, hex o mensaje de error)."""
    if text_bytes(text) > MAX_TEXT_BYTES:
        return False, "El texto ocupa %d bytes; el maximo es %d." % (text_bytes(text), MAX_TEXT_BYTES)
    ok, out, err = run_ciber(exe, ["enc-text", text, key])
    return (True, out) if ok else (False, err)


def decrypt_text(exe, hex_text, key):
    """Descifra un hexadecimal. Devuelve (ok, texto o mensaje de error)."""
    # Se quitan espacios y saltos de linea para que pegar un cifrado partido funcione
    compact = "".join(hex_text.split())
    ok, out, err = run_ciber(exe, ["dec-text", compact, key])
    return (True, out) if ok else (False, err)


def show_tables(exe, key):
    """Tablas que salen de la clave. Devuelve (ok, tablas o mensaje de error)."""
    ok, out, err = run_ciber(exe, ["tables", key])
    return (True, out) if ok else (False, err)


class CiberApp:
    """Ventana principal: clave, texto original arriba y cifrado (hexadecimal) abajo."""

    def __init__(self, root):
        self.root = root
        root.title("KDSPN-64 - cifrado de juguete")
        root.minsize(640, 520)

        # Ruta del ejecutable
        top = tk.Frame(root)
        top.pack(fill="x", padx=10, pady=(10, 4))
        tk.Label(top, text="Programa ciber:").pack(side="left")
        self.exe_var = tk.StringVar(value=default_exe_path())
        tk.Entry(top, textvariable=self.exe_var).pack(side="left", fill="x", expand=True, padx=4)
        tk.Button(top, text="...", command=self.pick_exe).pack(side="left")

        # Clave
        key_row = tk.Frame(root)
        key_row.pack(fill="x", padx=10, pady=4)
        tk.Label(key_row, text="Clave:").pack(side="left")
        self.key_var = tk.StringVar(value="0123456789ABCDEF")
        tk.Entry(key_row, textvariable=self.key_var, width=40).pack(side="left", padx=4)
        tk.Label(key_row, text="(1 a 16 caracteres o 32 digitos hexadecimales)", fg="gray30").pack(side="left")

        # Texto original
        tk.Label(root, text="Texto original:").pack(anchor="w", padx=10)
        self.plain = scrolledtext.ScrolledText(root, height=6, wrap="word", undo=True)
        self.plain.pack(fill="both", expand=True, padx=10)
        self.counter = tk.Label(root, anchor="e")
        self.counter.pack(fill="x", padx=10)
        self.plain.bind("<<Modified>>", self.update_counter)

        # Botones de cifrar y descifrar
        mid = tk.Frame(root)
        mid.pack(pady=6)
        tk.Button(mid, text="Cifrar ↓", width=14, command=self.do_encrypt).pack(side="left", padx=6)
        tk.Button(mid, text="Descifrar ↑", width=14, command=self.do_decrypt).pack(side="left", padx=6)

        # Texto cifrado (hexadecimal, editable para poder pegar un cifrado)
        tk.Label(root, text="Texto cifrado (hexadecimal):").pack(anchor="w", padx=10)
        self.cipher = scrolledtext.ScrolledText(root, height=6, wrap="char", font=("Consolas", 10))
        self.cipher.pack(fill="both", expand=True, padx=10)

        # Archivos y tablas
        bottom = tk.Frame(root)
        bottom.pack(fill="x", padx=10, pady=10)
        tk.Button(bottom, text="Abrir archivo", command=self.open_file).pack(side="left")
        tk.Button(bottom, text="Guardar resultado", command=self.save_file).pack(side="left", padx=6)
        tk.Button(bottom, text="Ver tablas", command=self.do_tables).pack(side="right")

        # "Cuadro activo": el ultimo en el que se hizo clic; ahi abren y guardan los botones
        self.active = self.plain
        self.plain.bind("<FocusIn>", lambda _e: self.set_active(self.plain))
        self.cipher.bind("<FocusIn>", lambda _e: self.set_active(self.cipher))
        self.update_counter()

    # --- utilidades de la ventana ---

    def set_active(self, box):
        self.active = box

    def get_text(self, box):
        return box.get("1.0", "end-1c")  # end-1c: sin el salto de linea que Tk agrega al final

    def set_text(self, box, text):
        box.delete("1.0", "end")
        box.insert("1.0", text)

    def update_counter(self, _event=None):
        n = text_bytes(self.get_text(self.plain))
        self.counter.config(text="%d / %d bytes" % (n, MAX_TEXT_BYTES),
                            fg="red" if n > MAX_TEXT_BYTES else "gray30")
        self.plain.edit_modified(False)  # para que <<Modified>> vuelva a dispararse

    def error(self, msg):
        messagebox.showerror("KDSPN-64", msg)

    # --- acciones de los botones ---

    def pick_exe(self):
        path = filedialog.askopenfilename(title="Selecciona ciber.exe",
                                          filetypes=[("Programa", "*.exe"), ("Todos", "*.*")])
        if path:
            self.exe_var.set(path)

    def do_encrypt(self):
        ok, result = encrypt_text(self.exe_var.get(), self.get_text(self.plain), self.key_var.get())
        if ok:
            self.set_text(self.cipher, result)
        else:
            self.error(result)

    def do_decrypt(self):
        ok, result = decrypt_text(self.exe_var.get(), self.get_text(self.cipher), self.key_var.get())
        if ok:
            self.set_text(self.plain, result)
            self.update_counter()
        else:
            self.error(result)

    def do_tables(self):
        ok, result = show_tables(self.exe_var.get(), self.key_var.get())
        if not ok:
            self.error(result)
            return
        win = tk.Toplevel(self.root)
        win.title("Tablas de la clave: %s" % self.key_var.get())
        box = scrolledtext.ScrolledText(win, width=110, height=30, font=("Consolas", 10))
        box.pack(fill="both", expand=True)
        box.insert("1.0", "Estas tablas salen de la clave: si cambias la clave, cambian.\n\n" + result)
        box.config(state="disabled")

    def open_file(self):
        path = filedialog.askopenfilename(title="Abrir archivo de texto")
        if not path:
            return
        try:
            with open(path, "rb") as f:
                text = f.read().decode("utf-8", errors="replace")
        except OSError as e:
            self.error("No se pudo abrir el archivo:\n%s" % e)
            return
        self.set_text(self.active, text)
        self.update_counter()

    def save_file(self):
        path = filedialog.asksaveasfilename(title="Guardar resultado", defaultextension=".txt")
        if not path:
            return
        try:
            with open(path, "wb") as f:
                f.write(self.get_text(self.active).encode("utf-8"))
        except OSError as e:
            self.error("No se pudo guardar el archivo:\n%s" % e)


def main():
    root = tk.Tk()
    CiberApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

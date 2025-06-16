import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import pefile
import capstone
import os
import struct
import binascii
import webbrowser
import ctypes
import sys

ICON_PATH = os.path.join(os.path.dirname(__file__), "xlpee.ico")

class XLPEE:
    def __init__(self, root):
        self.root = root
        self.root.iconbitmap(ICON_PATH)
        self.root.title("XLPEE - Xlaner PE Explorer & Editor")
        self.filename = ""
        self.pe = None
        self.hex_data = b""
        self.disasm_lines = []
        self.addr_to_offset = {}

        self.create_ui()

    def create_ui(self):
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Open", command=self.open_file)
        file_menu.add_command(label="Save Patched", command=self.save_file)
        file_menu.add_command(label="Patch Byte", command=self.patch_byte)
        file_menu.add_separator()
        file_menu.add_command(label="Export Disasm", command=self.export_disasm)
        file_menu.add_command(label="Export Hexdump", command=self.export_hexdump)
        file_menu.add_separator()
        file_menu.add_command(label="Open in Explorer", command=self.open_in_explorer)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        search_menu = tk.Menu(menubar, tearoff=0)
        search_menu.add_command(label="Find String", command=self.find_string)
        search_menu.add_command(label="Find Hex", command=self.find_hex)
        menubar.add_cascade(label="Search", menu=search_menu)

        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Analyze Sections & Exports", command=self.analyze_sections_exports)
        view_menu.add_command(label="Build Call Graph", command=self.build_call_graph)
        view_menu.add_command(label="Entropy View", command=self.entropy_view)
        view_menu.add_command(label="Resources", command=self.show_resources)
        view_menu.add_command(label="TLS Callbacks", command=self.show_tls_callbacks)
        view_menu.add_command(label="Digital Signature", command=self.show_signature)
        view_menu.add_command(label="PE Info", command=self.show_pe_info)
        view_menu.add_command(label="Open VirusTotal", command=self.open_virustotal)
        menubar.add_cascade(label="Analyze", menu=view_menu)

        nav_menu = tk.Menu(menubar, tearoff=0)
        nav_menu.add_command(label="Goto RVA", command=self.goto_rva)
        nav_menu.add_command(label="Goto Offset", command=self.goto_offset)
        menubar.add_cascade(label="Navigate", menu=nav_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.root.config(menu=menubar)

        top = tk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        top.pack(fill=tk.BOTH, expand=True)

        self.tree_funcs = tk.Listbox(top)
        self.tree_funcs.bind("<Double-Button-1>", self.navigate_to_symbol)
        self.tree_funcs.bind("<Button-3>", self.copy_selected)
        top.add(self.tree_funcs, width=250)

        mid = tk.PanedWindow(top, orient=tk.VERTICAL)
        top.add(mid)

        self.text_disasm = tk.Text(mid, bg="black", fg="lime", insertbackground="white")
        self.text_disasm.bind("<Double-Button-1>", self.jump_to_address)
        self.text_disasm.bind("<Control-c>", self.copy_text)
        mid.add(self.text_disasm)

        self.text_hex = tk.Text(mid, bg="black", fg="orange", insertbackground="white")
        self.text_hex.bind("<Control-c>", self.copy_text)
        mid.add(self.text_hex, height=200)

        self.tree_imports = ttk.Treeview(top)
        self.tree_imports.heading("#0", text="Imports")
        top.add(self.tree_imports, width=250)

        self.status = tk.Label(self.root, text="Ready", anchor="w")
        self.status.pack(fill=tk.X)

        # Progress bar for loading
        self.progress = ttk.Progressbar(self.root, orient="horizontal", mode="determinate")
        self.progress.pack(fill=tk.X)
        self.progress.pack_forget()

    def set_widgets_state(self, state):
        widgets = [
            self.tree_funcs, self.text_disasm, self.text_hex, self.tree_imports
        ]
        for w in widgets:
            try:
                w.config(state=state)
            except Exception:
                pass

    def open_file(self):
        path = filedialog.askopenfilename(filetypes=[("PE Files", "*.exe;*.dll")])
        if not path:
            return
        try:
            self.filename = path
            self.status.config(text="Loading: " + os.path.basename(path))
            self.set_widgets_state("disabled")
            self.progress.pack(fill=tk.X)
            self.root.update_idletasks()
            self.hex_data = self._read_file_with_progress(path)
            self.pe = pefile.PE(data=self.hex_data)
            self.status.config(text="Loaded: " + os.path.basename(path))
            self.populate_views()
        except Exception as e:
            messagebox.showerror("Error", str(e))
        finally:
            self.progress.pack_forget()
            self.set_widgets_state("normal")

    def _read_file_with_progress(self, path, chunk_size=1024 * 1024):
        filesize = os.path.getsize(path)
        self.progress["maximum"] = filesize
        data = bytearray()
        with open(path, "rb") as f:
            read = 0
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                data.extend(chunk)
                read += len(chunk)
                self.progress["value"] = read
                self.status.config(text=f"Loading: {os.path.basename(path)} ({read}/{filesize} bytes)")
                self.root.update_idletasks()
        self.progress["value"] = filesize
        return bytes(data)

    def save_file(self):
        path = filedialog.asksaveasfilename(defaultextension=".patched")
        if path:
            with open(path, "wb") as f:
                f.write(self.hex_data)
            self.status.config(text=f"Saved to: {path}")

    def patch_byte(self):
        addr = tk.simpledialog.askstring("Patch", "Enter RVA (hex):", parent=self.root)
        val = tk.simpledialog.askstring("Patch", "New byte (hex):", parent=self.root)
        try:
            rva = int(addr, 16)
            offset = self.pe.get_offset_from_rva(rva)
            byte_val = bytes.fromhex(val)
            self.hex_data = self.hex_data[:offset] + byte_val + self.hex_data[offset+len(byte_val):]
            self.status.config(text=f"Patched {addr} => {val}")
            self.populate_views()
        except Exception as e:
            messagebox.showerror("Error", f"Invalid input: {e}", parent=self.root)

    def populate_views(self):
        self.disassemble()
        self.load_hex()
        self.load_imports()

    def disassemble(self):
        self.text_disasm.config(state="normal")
        self.text_disasm.delete("1.0", tk.END)
        self.tree_funcs.delete(0, tk.END)
        try:
            text_section = next(s for s in self.pe.sections if b".text" in s.Name)
            code = text_section.get_data()
            base = self.pe.OPTIONAL_HEADER.ImageBase + text_section.VirtualAddress
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32 if self.pe.FILE_HEADER.Machine == 0x14c else capstone.CS_MODE_64)
            md.detail = True
            self.disasm_lines = []
            self.addr_to_offset = {}
            for insn in md.disasm(code, base):
                line = f"{insn.address:08X}: {insn.mnemonic} {insn.op_str}"
                self.text_disasm.insert(tk.END, line + "\n")
                self.disasm_lines.append((insn.address, line))
                self.addr_to_offset[insn.address] = insn.address - base + text_section.PointerToRawData
                if insn.mnemonic.startswith("call") or insn.mnemonic.startswith("jmp"):
                    self.tree_funcs.insert(tk.END, f"{insn.address:08X} -> {insn.op_str}")
        except Exception as e:
            self.text_disasm.insert(tk.END, f"Error in disassembly: {e}\n")
        self.text_disasm.config(state="normal")

    def load_hex(self):
        self.text_hex.config(state="normal")
        self.text_hex.delete("1.0", tk.END)
        lines = []
        for i in range(0, len(self.hex_data), 16):
            chunk = self.hex_data[i:i+16]
            hex_chunk = ' '.join(f"{b:02X}" for b in chunk)
            ascii_chunk = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            lines.append(f"{i:08X}: {hex_chunk:<48} {ascii_chunk}")
        self.text_hex.insert(tk.END, '\n'.join(lines))
        self.text_hex.config(state="normal")

    def load_imports(self):
        for i in self.tree_imports.get_children():
            self.tree_imports.delete(i)
        try:
            for entry in getattr(self.pe, "DIRECTORY_ENTRY_IMPORT", []):
                parent = self.tree_imports.insert('', 'end', text=entry.dll.decode(errors="ignore"))
                for imp in entry.imports:
                    self.tree_imports.insert(parent, 'end', text=imp.name.decode(errors="ignore") if imp.name else f"Ordinal {imp.ordinal}")
        except AttributeError:
            self.tree_imports.insert('', 'end', text="No imports found")

    def find_string(self):
        query = tk.simpledialog.askstring("Find", "Enter ASCII string:", parent=self.root)
        if not query:
            return
        found = []
        index = 0
        while index < len(self.hex_data):
            index = self.hex_data.find(query.encode(), index)
            if index == -1:
                break
            found.append(index)
            index += 1
        if not found:
            messagebox.showinfo("Find", f"'{query}' not found.")
        else:
            messagebox.showinfo("Found", f"Found {len(found)} matches at offsets: {', '.join(hex(x) for x in found)}")

    def find_hex(self):
        query = tk.simpledialog.askstring("Find Hex", "Enter hex string (e.g. 90 90 90):", parent=self.root)
        if not query:
            return
        try:
            pattern = bytes.fromhex(query)
        except Exception:
            messagebox.showerror("Error", "Invalid hex string")
            return
        found = []
        index = 0
        while index < len(self.hex_data):
            index = self.hex_data.find(pattern, index)
            if index == -1:
                break
            found.append(index)
            index += 1
        if not found:
            messagebox.showinfo("Find Hex", f"Pattern not found.")
        else:
            messagebox.showinfo("Found", f"Found {len(found)} matches at offsets: {', '.join(hex(x) for x in found)}")

    def jump_to_address(self, event):
        try:
            index = self.text_disasm.index(tk.CURRENT)
            line = self.text_disasm.get(index + " linestart", index + " lineend")
            addr = int(line.split(':')[0], 16)
            offset = self.addr_to_offset.get(addr)
            if offset is not None:
                self.text_hex.see(f"{offset:08X}.0")
        except Exception:
            pass

    def navigate_to_symbol(self, event):
        try:
            selection = self.tree_funcs.curselection()
            if not selection:
                return
            value = self.tree_funcs.get(selection[0])
            addr = int(value.split(' ')[0], 16)
            for i, (a, line) in enumerate(self.disasm_lines):
                if a == addr:
                    self.text_disasm.see(f"{i+1}.0")
                    break
        except Exception:
            pass

    def analyze_sections_exports(self):
        sections_info = "Sections:\n"
        for s in self.pe.sections:
            sections_info += f"{s.Name.decode(errors='ignore').strip()} - VA: {hex(s.VirtualAddress)}, Size: {hex(s.SizeOfRawData)}\n"

        exports_info = "\nExports:\n"
        try:
            for exp in getattr(self.pe, "DIRECTORY_ENTRY_EXPORT", []).symbols:
                name = exp.name.decode(errors="ignore") if exp.name else f"Ordinal {exp.ordinal}"
                exports_info += f"{name} - RVA: {hex(exp.address)}\n"
        except AttributeError:
            exports_info += "No exports found."

        messagebox.showinfo("Sections & Exports", sections_info + exports_info)

    def build_call_graph(self):
        calls = []
        for addr, line in self.disasm_lines:
            if 'call' in line:
                calls.append(line)
        if not calls:
            messagebox.showinfo("Call Graph", "No calls found.")
        else:
            messagebox.showinfo("Call Graph", "\n".join(calls))

    def entropy_view(self):
        try:
            import math
            entropies = []
            for section in self.pe.sections:
                data = section.get_data()
                if not data:
                    continue
                occur = [0] * 256
                for b in data:
                    occur[b] += 1
                entropy = -sum(p * math.log2(p) for p in (c / len(data) for c in occur if c))
                entropies.append(f"{section.Name.decode(errors='ignore').strip()} - Entropy: {entropy:.2f}")
            messagebox.showinfo("Entropy View", "\n".join(entropies))
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def show_resources(self):
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
                res = []
                for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    res.append(f"Type: {entry.name or entry.struct.Id}")
                messagebox.showinfo("Resources", "\n".join(res) if res else "No resources found")
            else:
                messagebox.showinfo("Resources", "No resources found")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def show_tls_callbacks(self):
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_TLS'):
                tls = self.pe.DIRECTORY_ENTRY_TLS
                cb_list = []
                if tls.struct.AddressOfCallBacks:
                    addr = tls.struct.AddressOfCallBacks - self.pe.OPTIONAL_HEADER.ImageBase
                    offset = self.pe.get_offset_from_rva(addr)
                    while True:
                        if self.pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE:
                            cb = struct.unpack_from("<I", self.hex_data, offset)[0]
                            step = 4
                        else:
                            cb = struct.unpack_from("<Q", self.hex_data, offset)[0]
                            step = 8
                        if cb == 0:
                            break
                        cb_list.append(f"Callback: 0x{cb:X}")
                        offset += step
                if cb_list:
                    messagebox.showinfo("TLS Callbacks", "\n".join(cb_list))
                else:
                    messagebox.showinfo("TLS Callbacks", "No TLS callbacks found")
            else:
                messagebox.showinfo("TLS Callbacks", "No TLS directory")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def show_signature(self):
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_SECURITY'):
                sec = self.pe.DIRECTORY_ENTRY_SECURITY
                messagebox.showinfo("Digital Signature", f"Security Directory found at offset {hex(sec.struct.VirtualAddress)}")
            else:
                messagebox.showinfo("Digital Signature", "No digital signature found")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def show_pe_info(self):
        try:
            info = []
            info.append(f"File: {os.path.basename(self.filename)}")
            info.append(f"Machine: {hex(self.pe.FILE_HEADER.Machine)}")
            info.append(f"Bitness: {'64-bit' if self.pe.FILE_HEADER.Machine == 0x8664 else '32-bit'}")
            info.append(f"Compiler Timestamp: {self.pe.FILE_HEADER.TimeDateStamp}")
            info.append(f"Number of Sections: {self.pe.FILE_HEADER.NumberOfSections}")
            info.append(f"Entry Point: {hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
            info.append(f"Image Base: {hex(self.pe.OPTIONAL_HEADER.ImageBase)}")
            messagebox.showinfo("PE Info", "\n".join(info))
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def open_virustotal(self):
        if self.filename:
            import hashlib
            sha256 = hashlib.sha256(self.hex_data).hexdigest()
            url = f"https://www.virustotal.com/gui/file/{sha256}"
            webbrowser.open(url)

    def goto_rva(self):
        rva = tk.simpledialog.askstring("Goto RVA", "Enter RVA (hex):", parent=self.root)
        try:
            rva = int(rva, 16)
            offset = self.pe.get_offset_from_rva(rva)
            self.text_hex.see(f"{offset:08X}.0")
        except Exception as e:
            messagebox.showerror("Error", f"Invalid RVA: {e}")

    def goto_offset(self):
        offset = tk.simpledialog.askstring("Goto Offset", "Enter file offset (hex):", parent=self.root)
        try:
            offset = int(offset, 16)
            self.text_hex.see(f"{offset:08X}.0")
        except Exception as e:
            messagebox.showerror("Error", f"Invalid offset: {e}")

    def export_disasm(self):
        path = filedialog.asksaveasfilename(defaultextension=".asm")
        if path:
            with open(path, "w") as f:
                f.write(self.text_disasm.get("1.0", tk.END))
            self.status.config(text=f"Disasm exported to {path}")

    def export_hexdump(self):
        path = filedialog.asksaveasfilename(defaultextension=".hex")
        if path:
            with open(path, "w") as f:
                f.write(self.text_hex.get("1.0", tk.END))
            self.status.config(text=f"Hexdump exported to {path}")

    def open_in_explorer(self):
        if self.filename:
            import subprocess
            folder = os.path.dirname(os.path.abspath(self.filename))
            if os.name == "nt":
                os.startfile(folder)
            else:
                subprocess.Popen(["xdg-open", folder])

    def show_about(self):
        messagebox.showinfo("About", "XLPEE - Xlaner PE Explorer & Editor Ultimate\nby Xlaner\n2025\n\nFeatures:\n- PE structure analysis\n- Disassembly\n- Hex editing\n- Imports/Exports\n- Entropy\n- Resources\n- TLS\n- Digital Signature\n- VirusTotal\n- And more!")

    def copy_text(self, event=None):
        widget = event.widget
        try:
            text = widget.get(tk.SEL_FIRST, tk.SEL_LAST)
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
        except tk.TclError:
            pass

    def copy_selected(self, event=None):
        try:
            selection = self.tree_funcs.curselection()
            if selection:
                value = self.tree_funcs.get(selection[0])
                self.root.clipboard_clear()
                self.root.clipboard_append(value)
        except Exception:
            pass

    def winico(self):
        try:

            if sys.platform != "win32":
                return

            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32
            GCL_HICON = -14
            GCL_HICONSM = -34
            WM_SETICON = 0x0080
            ICON_BIG = 1
            ICON_SMALL = 0

            import ctypes.wintypes
            LoadImage = ctypes.windll.user32.LoadImageW
            LR_LOADFROMFILE = 0x00000010
            hicon = LoadImage(0, ICON_PATH, 1, 0, 0, LR_LOADFROMFILE)

            if not hicon:
                return

            def enumwindowsproc(hwnd, lParam):
                if not user32.IsWindowVisible(hwnd):
                    return True
                user32.SendMessageW(hwnd, WM_SETICON, ICON_BIG, hicon)
                user32.SendMessageW(hwnd, WM_SETICON, ICON_SMALL, hicon)
                if not user32.GetClassLongPtrW(hwnd, GCL_HICON):
                    user32.SetClassLongPtrW(hwnd, GCL_HICON, hicon)
                if not user32.GetClassLongPtrW(hwnd, GCL_HICONSM):
                    user32.SetClassLongPtrW(hwnd, GCL_HICONSM, hicon)
                return True

            EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM)
            user32.EnumWindows(EnumWindowsProc(numwindowsproc), 0)
        except Exception:
            pass


if __name__ == '__main__':
    root = tk.Tk()
    app = XLPEE(root)
    app.winico()
    root.mainloop()

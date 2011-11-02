// Copyright (c) 2005 VMware, Inc.

// This is a translation of http://git.gnome.org/browse/meld/tree/meld/ui/wraplabel.py,
// which in turn is a translation of WrapLabel from libview.

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Python translation from wrapLabel.{cc|h} by Gian Mario Tagliaretti
// Vala translation from wraplabel.py by Zbigniew Jędrzejewski-Szmek

public class WrapLabel : Gtk.Label {
        private int _wrap_width;

        public WrapLabel(string? text = null) {
                this._wrap_width = 0;
                var layout = get_layout();
                layout.set_wrap(Pango.WrapMode.WORD_CHAR);
                if (text != null)
                        this.set_text(text);
                this.set_alignment(0, 0);
        }

        public override void size_request(out Gtk.Requisition requisition) {
                int width, height;
                var layout = get_layout();
                layout.get_pixel_size(out width, out height);
                requisition.width = 0;
                requisition.height = height;
        }

        public override void size_allocate(Gdk.Rectangle allocation) {
                base.size_allocate (allocation);
                this._set_wrap_width(allocation.width);
        }

        public new void set_text(string str) {
                base.set_text(str);
                this._set_wrap_width(this._wrap_width);
        }

        public new void set_markup(string str) {
                base.set_markup(str);
                this._set_wrap_width(this._wrap_width);
        }

        private void _set_wrap_width(int width) {
                if (width == 0)
                        return;

                var layout = get_layout();
                layout.set_width(width * Pango.SCALE);
                if (_wrap_width != width) {
                        this._wrap_width = width;
                        this.queue_resize();
                }
        }
}

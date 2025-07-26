import threading
from PIL import Image


class AndroidDisplay:
    """Kivy based display driver for running SeedSigner on Android."""

    def __init__(self, display_type: str = "android", width: int = 320, height: int = 240):
        self.display_type = display_type
        self._width = width
        self._height = height
        self._app = None
        self._image_widget = None
        self._start_app()

    # Properties expected by Renderer
    @property
    def width(self):
        return self._width

    @property
    def height(self):
        return self._height

    def invert(self, enabled: bool = True):
        # Not implemented; colors are rendered directly
        pass

    def _start_app(self):
        """Start a minimal Kivy app showing an Image widget."""
        from kivy.app import App
        from kivy.uix.image import Image as KivyImage
        from kivy.uix.floatlayout import FloatLayout
        from kivy.core.window import Window

        display = self

        class DisplayApp(App):
            def build(self_inner):
                Window.size = (display._width, display._height)
                layout = FloatLayout()
                display._image_widget = KivyImage()
                layout.add_widget(display._image_widget)
                return layout

        self._app = DisplayApp()
        threading.Thread(target=self._app.run, daemon=True).start()

    def show_image(self, image: Image.Image, x_start: int = 0, y_start: int = 0):
        """Render a PIL Image to the screen."""
        from kivy.clock import Clock
        from kivy.graphics.texture import Texture

        if self._image_widget is None:
            return

        img = image.resize((self._width, self._height)).convert("RGBA")
        tex = Texture.create(size=img.size)
        tex.blit_buffer(img.tobytes(), colorfmt="rgba", bufferfmt="ubyte")

        def update(dt):
            self._image_widget.texture = tex

        Clock.schedule_once(update, 0)

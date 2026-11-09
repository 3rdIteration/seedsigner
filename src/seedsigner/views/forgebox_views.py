"""BIP85 ForgeBox key recovery, public export and explicit offline signing.

All operation screens live in one View, so Back never replays a signing action.
No private material is written, logged, placed in destinations or cached.
"""
from gettext import gettext as _
from seedsigner.gui.components import GUIConstants, reflow_text_into_pages
from seedsigner.gui.screens import ButtonListScreen, WarningScreen
from seedsigner.gui.screens.screen import ButtonOption, PagedTextScreen
from seedsigner.gui.screens.seed_screens import SeedBIP85SelectChildIndexScreen
from seedsigner.hardware.microsd import MicroSD
from seedsigner.helpers import forgebox_tools
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.views.view import View, Destination, BackStackView


def _groups(value):
    return ' '.join(value[i:i+4] for i in range(0, len(value), 4))


class ToolsForgeBoxMenuView(View):
    EXPORT = ButtonOption('Export BIP85 Public Key')
    SIGN = ButtonOption('Sign Request on Card')

    def run(self):
        if not forgebox_tools.is_available():
            return Destination(BackStackView)
        buttons = [self.EXPORT, self.SIGN]
        selected = self.run_screen(ButtonListScreen, title=_('ForgeBox Signing'), button_data=buttons)
        if selected not in (0, 1):
            return Destination(BackStackView)
        return Destination(ToolsForgeBoxRunView, view_args={'action': 'export' if selected == 0 else 'sign'})


class ToolsForgeBoxRunView(View):
    def __init__(self, action):
        super().__init__()
        if action not in ('export', 'sign'):
            raise ValueError('unknown ForgeBox action')
        self.action = action

    def show_text(self, title, text):
        width, height = PagedTextScreen.get_paging_dimensions()
        pages = reflow_text_into_pages(text=text, width=width, height=height,
                                      font_size=GUIConstants.get_body_font_size())
        for page in range(len(pages)):
            if self.run_screen(PagedTextScreen, title=title, paged_info=pages, page_num=page) != 0:
                return False
        return True

    def run(self):
        key = None
        try:
            tools = forgebox_tools.load()
            card = str(MicroSD.get_microsd_dir())
            # Read once before review; a swapped request is never re-read for signing.
            request = tools.validate_request(tools.read_json(card, 'request.json')) if self.action == 'sign' else None
            if request is not None:
                registering = request['action'] == 'register'
                selected = self.run_screen(WarningScreen, title=_('ForgeBox Signing'),
                    status_headline=_('Register owner key') if registering else _('Digest-only signing'),
                    text=_('Registration binds a lifetime firmware key. Compare the full public key on ForgeBox.')
                         if registering else _('The firmware is not on this device. Only sign hashes prepared on your trusted PC.'),
                    button_data=[ButtonOption('Review')])
                if selected != 0:
                    return Destination(BackStackView)
                if registering:
                    review = _('Registration mode: {}\nNonce: {}').format(
                        'legacy' if request['legacy'] else 'challenge', _groups(request['nonce']) or '(none)')
                else:
                    review = _('Label: {}\nOriginal size: {}\nOriginal SHA256:\n{}\nCompressed SHA256:\n{}').format(
                        ' '.join(request['name'][i:i+12] for i in range(0, len(request['name']), 12)),
                        request['original_size'], _groups(request['original_hash']), _groups(request['compressed_hash']))
                if not self.show_text(_('Review Request'), review):
                    return Destination(BackStackView)
            seeds = self.controller.storage.seeds
            if not seeds:
                self.show_text(_('Load a seed first'), _('Load the signing seed, then return to ForgeBox Signing.'))
                return Destination(BackStackView)
            network = self.settings.get_value(SettingsConstants.SETTING__NETWORK)
            selected = self.run_screen(ButtonListScreen, title=_('Signing Seed'),
                button_data=[ButtonOption(seed.get_fingerprint(network)) for seed in seeds])
            if type(selected) is not int or not 0 <= selected < len(seeds):
                return Destination(BackStackView)
            index = self.run_screen(SeedBIP85SelectChildIndexScreen, title=_('ForgeBox Key Index'))
            if not isinstance(index, str):
                return Destination(BackStackView)
            # get_root supports mnemonic-backed seeds and XprvSeed (seed_bytes=None).
            key = tools.key_from_root(seeds[selected].get_root(network), int(index))
            public = tools.public_hex(key)
            if request is not None and request['public_key'] != public:
                self.show_text(_('Wrong signing key'), _('Seed, passphrase or BIP85 index does not match this request.'))
                return Destination(BackStackView)
            if not self.show_text(_('Signing Public Key'),
                    "BIP85 path:\nm/83696968'/2'/\n%s'\nSHA256 key ID:\n%s\nPublic key:\n%s" %
                    (index, _groups(tools.fingerprint(public)), _groups(public[2:]))):
                return Destination(BackStackView)
            selected = self.run_screen(WarningScreen, title=_('ForgeBox Signing'), status_headline=None,
                text=_('Only the public key is saved. Record the seed, passphrase and index for recovery.')
                     if self.action == 'export' else _('Authorize this exact request with the displayed signing key?'),
                button_data=[ButtonOption('Export' if self.action == 'export' else 'Sign')])
            if selected != 0:
                return Destination(BackStackView)
            if self.action == 'export':
                tools.export_public(card, key, int(index))
                message = _('Public key saved in forgebox-signing/. Verify recovery before registration.')
            else:
                response = tools.sign_request(request, key)
                tools.write_json(card, 'response.json', response)
                message = _('Response saved. Return the card to your PC to verify and assemble or register.')
            # Drop our key reference before showing completion; no shared key cache.
            key = None
            self.show_text(_('ForgeBox Complete'), message)
        except Exception:
            # Exceptions may carry key-library objects: do not log/format them.
            key = None
            self.show_text(_('Cannot continue'), _('Check the card request, OS tools and signing seed. No private key was saved.'))
        finally:
            key = None
        # Multiple-screen operation terminates at its entry menu, never an action.
        return Destination(ToolsForgeBoxMenuView)

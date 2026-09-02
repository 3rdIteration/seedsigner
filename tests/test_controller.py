import pytest

# Must import this before the Controller
from base import BaseTest, FlowTest, FlowStep

from seedsigner.controller import Controller
from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON, ButtonListScreen, ButtonOption
from seedsigner.views.view import BackStackView, Destination, View


class TestController(BaseTest):

    def test_reset_controller(self):
        """ The reset_controller util should completely reset the Controller singleton """
        controller = Controller.get_instance()
        controller.address_explorer_data = "foo"

        BaseTest.reset_controller()
        controller = Controller.get_instance()
        assert controller.address_explorer_data is None


    def test_singleton_init_fails(self):
        """ The Controller should not allow any code to instantiate it via Controller() """
        with pytest.raises(Exception):
            c = Controller()


    def test_handle_exception(reset_controller):
        """ Handle exceptions that get caught by the controller """

        def process_exception_asserting_valid_error(exception_type, exception_msg=None):
            """
            Exceptions caught by the controller are forwarded to the
            UnhandledExceptionView with view_args["error"] being a list
            of three strings, ie: [exception_type, line_info, exception_msg]
            """
            try:
                if exception_msg:
                    raise exception_type(exception_msg)
                else:
                    raise exception_type()
            except Exception as e:
                error = controller.handle_exception(e).view_args["error"]

            # assert that error structure is valid
            assert len(error) == 3
            assert error[0] in str(exception_type)
            assert type(error[1]) == str
            if exception_msg:
                assert exception_msg in error[2]
            else:
                assert error[2] == ""

        # Initialize the controller
        controller = Controller.get_instance()

        exception_tests = [
            # exceptions with an exception_msg
            (Exception, "foo"),
            (KeyError, "key not found"),
            # exceptions without an exception_msg
            (Exception, ""),
            (Exception, None),
        ]
            
        for exception_type, exception_msg in exception_tests:
            process_exception_asserting_valid_error(exception_type, exception_msg)


    def test_singleton_get_instance_preserves_state(self):
        """ Changes to the Controller singleton should be preserved across calls to get_instance() """

        # Initialize the instance and verify that it read the config settings
        controller = Controller.get_instance()
        assert controller.unverified_address is None

        # Change a value in the instance...
        controller.unverified_address = "123abc"

        # ...get a new copy of the instance and confirm change
        controller = Controller.get_instance()
        assert controller.unverified_address == "123abc"



"""
    Minimal Views used to exercise the Controller's back_stack handling in
    isolation: a two-level menu tree (parent menu -> entry menu) plus the
    workflows that an entry menu can launch.

    Note that the Controller never pushes the *initial* Destination onto the
    back_stack, so `BackStackRootView` is only a bootstrap and never appears in
    the assertions below.
"""
class BackStackRootView(View):
    def run(self):
        self.run_screen(ButtonListScreen, button_data=[ButtonOption("Next")])
        return Destination(BackStackParentMenuView)


class BackStackParentMenuView(View):
    def run(self):
        self.run_screen(ButtonListScreen, button_data=[ButtonOption("Next")])
        return Destination(BackStackEntryMenuView)


class BackStackEntryMenuView(View):
    """The menu a workflow is launched from, and that it returns to when done."""
    def run(self):
        ret = self.run_screen(ButtonListScreen, button_data=[ButtonOption("Next")])
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        return Destination([
            BackStackWorkflowView,
            BackStackClearHistoryView,
            BackStackSkippedView,
        ][ret])


class BackStackWorkflowView(View):
    """A complete workflow that ends by returning to the menu that launched it."""
    def run(self):
        self.run_screen(ButtonListScreen, button_data=[ButtonOption("Done")])
        return Destination(BackStackEntryMenuView)


class BackStackClearHistoryView(View):
    def run(self):
        self.run_screen(ButtonListScreen, button_data=[ButtonOption("Done")])
        return Destination(BackStackEntryMenuView, clear_history=True)


class BackStackSkippedView(View):
    """Forwards straight through; should not be left in the back_stack."""
    def run(self):
        self.run_screen(ButtonListScreen, button_data=[ButtonOption("Next")])
        return Destination(BackStackWorkflowView, skip_current_view=True)



class TestBackStack(FlowTest):
    """
        A workflow that finishes by returning to the menu it was launched from must
        not leave its own screens above that menu in the back_stack; "back" from the
        menu would then re-enter the workflow that just completed. Flows that
        dead-end on re-entry (e.g. "Uninstall Applet" with no applets left) loop with
        no way out but a power cycle. See issue #423.
    """

    def view_classes(self) -> list:
        return [d.View_cls for d in self.controller.back_stack]


    def test_completed_workflow_unwinds_the_back_stack(self):
        self.run_sequence([
            FlowStep(BackStackRootView, screen_return_value=0),
            FlowStep(BackStackParentMenuView, screen_return_value=0),
            FlowStep(BackStackEntryMenuView, screen_return_value=0),
            FlowStep(BackStackWorkflowView, screen_return_value=0),
            FlowStep(BackStackEntryMenuView),
        ])

        # The workflow's View is gone; only the entry menu and its parent remain.
        assert self.view_classes() == [BackStackParentMenuView, BackStackEntryMenuView]


    def test_back_from_entry_menu_skips_the_completed_workflow(self):
        """ "Back" from the entry menu must reach its parent, not re-run the workflow """
        self.run_sequence([
            FlowStep(BackStackRootView, screen_return_value=0),
            FlowStep(BackStackParentMenuView, screen_return_value=0),
            FlowStep(BackStackEntryMenuView, screen_return_value=0),
            FlowStep(BackStackWorkflowView, screen_return_value=0),
            FlowStep(BackStackEntryMenuView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(BackStackParentMenuView),
        ])


    def test_distinct_destinations_are_still_appended(self):
        """ Unwinding must only trigger on a Destination we have actually been to """
        self.run_sequence([
            FlowStep(BackStackRootView, screen_return_value=0),
            FlowStep(BackStackParentMenuView, screen_return_value=0),
            FlowStep(BackStackEntryMenuView, screen_return_value=0),
            FlowStep(BackStackWorkflowView),
        ])

        assert self.view_classes() == [
            BackStackParentMenuView,
            BackStackEntryMenuView,
            BackStackWorkflowView,
        ]


    def test_clear_history_still_wipes_the_back_stack(self):
        self.run_sequence([
            FlowStep(BackStackRootView, screen_return_value=0),
            FlowStep(BackStackParentMenuView, screen_return_value=0),
            FlowStep(BackStackEntryMenuView, screen_return_value=1),
            FlowStep(BackStackClearHistoryView, screen_return_value=0),
            FlowStep(BackStackEntryMenuView),
        ])

        assert self.view_classes() == [BackStackEntryMenuView]


    def test_skip_current_view_still_drops_the_forwarding_view(self):
        self.run_sequence([
            FlowStep(BackStackRootView, screen_return_value=0),
            FlowStep(BackStackParentMenuView, screen_return_value=0),
            FlowStep(BackStackEntryMenuView, screen_return_value=2),
            FlowStep(BackStackSkippedView, screen_return_value=0),
            FlowStep(BackStackWorkflowView),
        ])

        assert self.view_classes() == [
            BackStackParentMenuView,
            BackStackEntryMenuView,
            BackStackWorkflowView,
        ]

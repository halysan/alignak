# -*- coding: utf-8 -*-

import warnings

from .. import __version__
from alignak.misc.custom_module import CustomModule


class DeprecatedAlignakBin(CustomModule):

    @property
    def VERSION(self):
        """Any code importing, or using, `VERSION` from alignak.bin will have
        this deprecation warning emitted, *if* deprecation warnings are enabled."""
        warnings.warn(
            '`alignak.bin.VERSION` is deprecated version attribute'
            ' and will be removed in a future release.\n'
            'You must use `alignak.__version__` attribute by now.\n'
            'Please update your code accordingly.', DeprecationWarning, stacklevel=2)
        return __version__

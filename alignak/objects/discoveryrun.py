#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# Copyright (C) 2015-2015: Alignak team, see AUTHORS.txt file for contributors
#
# This file is part of Alignak.
#
# Alignak is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Alignak is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with Alignak.  If not, see <http://www.gnu.org/licenses/>.
#
#
# This file incorporates work covered by the following copyright and
# permission notice:
#
#  Copyright (C) 2009-2014:
#     Hartmut Goebel, h.goebel@goebel-consult.de
#     aviau, alexandre.viau@savoirfairelinux.com
#     Nicolas Dupeux, nicolas@dupeux.net
#     Grégory Starck, g.starck@gmail.com
#     Sebastien Coavoux, s.coavoux@free.fr
#     Thibault Cohen, titilambert@gmail.com
#     Jean Gabes, naparuba@gmail.com
#     Romain Forlot, rforlot@yahoo.com
#     Christophe SIMON, christophe.simon@dailymotion.com

#  This file is part of Shinken.
#
#  Shinken is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Affero General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  Shinken is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Affero General Public License for more details.
#
#  You should have received a copy of the GNU Affero General Public License
#  along with Shinken.  If not, see <http://www.gnu.org/licenses/>.

"""
This module provide Discoveryrun and Discoveryruns class used to discover hosts/services with
scan of network
"""

from copy import copy

from item import Item, Items

from alignak.objects.matchingitem import MatchingItem
from alignak.property import StringProp
from alignak.eventhandler import EventHandler
from alignak.macroresolver import MacroResolver


class Discoveryrun(MatchingItem):
    """
    Class to manage a discovery
    An Discoveryrun is used to discover hosts/services on network with a command
    """
    id = 1  # zero is always special in database, so we do not take risk here
    my_type = 'discoveryrun'

    properties = Item.properties.copy()
    properties.update({
        'discoveryrun_name': StringProp(),
        'discoveryrun_command': StringProp(),
    })

    running_properties = Item.running_properties.copy()
    running_properties.update({
        'current_launch': StringProp(default=None),
    })

    def __init__(self, params={}):
        """
        The init of a discovery will set the property of
        Discoveryrun.properties as in setattr, but all others
        will be in a list because we need to have all names
        and not lost all in __dict__

        :param params: dictionnary of parameters
        :type params: dict
        """
        cls = self.__class__

        # We have our own id of My Class type :)
        # use set attr for going into the slots
        # instead of __dict__ :)
        setattr(self, 'id', cls.id)
        cls.id += 1

        self.matches = {}  # for matching rules
        self.not_matches = {}  # for rules that should NOT match

        # In my own property:
        #  -> in __dict__
        # if not, in matches or not match (if key starts
        # with a !, it's a not rule)
        # -> in self.matches or self.not_matches
        # in writing properties if start with + (means 'add this')
        for key in params:
            # delistify attributes if there is only one value
            params[key] = self.compact_unique_attr_value(params[key])
            if key in cls.properties:
                setattr(self, key, params[key])
            else:
                if key.startswith('!'):
                    key = key.split('!')[1]
                    self.not_matches[key] = params['!' + key]
                else:
                    self.matches[key] = params[key]

        # Then running prop :)
        cls = self.__class__
        # adding running properties like latency, dependency list, etc
        for prop, entry in cls.running_properties.items():
            # Copy is slow, so we check type
            # Type with __iter__ are list or dict, or tuple.
            # Item need it's own list, so qe copy
            val = entry.default
            if hasattr(val, '__iter__'):
                setattr(self, prop, copy(val))
            else:
                setattr(self, prop, val)

            # each instance to have his own running prop!


    def get_name(self):
        """
        Output name

        :return: Name of discoveryrun
        :rtype: str
        """
        try:
            return self.discoveryrun_name
        except AttributeError:
            return "UnnamedDiscoveryRun"

    def is_first_level(self):
        """
        A Run that is first level means that it do not have
        any matching filter

        :return: true is it is first level
        :rtype: bool
        """
        return len(self.not_matches) + len(self.matches) == 0

    def launch(self, ctx=[], timeout=300):
        """
        Get an eventhandler object and launch it

        :param ctx: elements
        :type ctx: list
        :param timeout:it's the timeout in seconds
        :type timeout: int
        """
        m = MacroResolver()
        cmd = m.resolve_command(self.discoveryrun_command, ctx)
        self.current_launch = EventHandler(cmd, timeout=timeout)
        self.current_launch.execute()

    def check_finished(self):
        """
        Process code for finish launch
        """
        max_output = 10 ** 9
        # print "Max output", max_output
        self.current_launch.check_finished(max_output)

    def is_finished(self):
        """
        Check if the launch is finished

        :return: true if finished to run
        :rtype: bool
        """
        if self.current_launch is None:
            return True
        if self.current_launch.status in ('done', 'timeout'):
            return True
        return False

    def get_output(self):
        """
        Get the output of the launch
        we use an EventHandler object, so we have output with a single line
        and longoutput with the rest. We just need to return all

        :return: output of lunch
        :rtype: str
        """
        return '\n'.join([self.current_launch.output, self.current_launch.long_output])


class Discoveryruns(Items):
    """
    Class to manage list of Discoveryrun
    Discoveryruns is used to regroup all the Discoveryrun
    """
    name_property = "discoveryrun_name"
    inner_class = Discoveryrun

    def linkify(self, commands):
        """
        Link commands to Discoveryruns
        One command = one Discoveryrun

        :param commands: command objects
        :type commands: list of object
        """
        for r in self:
            r.linkify_one_command_with_commands(commands, 'discoveryrun_command')

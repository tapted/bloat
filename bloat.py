#!/usr/bin/python
#
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import operator
import optparse
import os
import re
import subprocess
import sys
import json


###################### HACK #####################
if "check_output" not in dir(subprocess): # duck punch it in!
    def f(*popenargs, **kwargs):
        if 'stdout' in kwargs:
            raise ValueError('stdout argument not allowed, it will be overridden.')
        process = subprocess.Popen(stdout=subprocess.PIPE, *popenargs, **kwargs)
        output, unused_err = process.communicate()
        retcode = process.poll()
        if retcode:
            cmd = kwargs.get("args")
            if cmd is None:
                cmd = popenargs[0]
            raise subprocess.CalledProcessError(retcode, cmd)
        return output
    subprocess.check_output = f
###################### HACK #####################


class Suffix:
    def __init__(self, suffix, replacement):
        self.pattern = '^(.*)' + suffix + '(.*)$'
        self.re = re.compile(self.pattern)
        self.replacement = replacement

class SuffixCleanup:
    """Pre-compile suffix regular expressions."""
    def __init__(self):
        self.suffixes = [
            Suffix('\.part\.([0-9]+)',      'part'),
            Suffix('\.constprop\.([0-9]+)', 'constprop'),
            Suffix('\.isra\.([0-9]+)',      'isra'),
        ]

    def cleanup(self, ident, cppfilt):
        """Cleanup identifiers that have suffixes preventing demangling,
           and demangle if possible."""
        to_append = []
        for s in self.suffixes:
            found = s.re.match(ident)
            if not found:
                continue
            to_append += [' [' + s.replacement + '.' + found.group(2) + ']']
            ident = found.group(1) + found.group(3)
        if len(to_append) > 0:
            # Only try to demangle if there were suffixes.
            ident = demangle(ident, cppfilt)
        for s in to_append:
            ident += s
        return ident

suffix_cleanup = SuffixCleanup()

def format_bytes(bytes):
    """Pretty-print a number of bytes."""
    if bytes > 1e6:
        bytes = bytes / 1.0e6
        return '%.1fm' % bytes
    if bytes > 1e3:
        bytes = bytes / 1.0e3
        return '%.1fk' % bytes
    return str(bytes)


def symbol_type_to_human(type):
    """Convert a symbol type as printed by nm into a human-readable name."""
    return {
        'b': 'bss',
        'd': 'data',
        'n': 'debugging symbol',
        'r': 'read-only data',
        't': 'code',
        'u': 'weak symbol', # Unique global.
        'w': 'weak symbol',
        'v': 'weak symbol'
        }[type]


def process_no_addres_match(match):
    symbol_type, _ = match.groups()
    if symbol_type in ('U', 'w'):
        # external or weak symbol
        return True


def process_no_size_match(match):
    '''
    @author: rlmajewski
    This function is here only to denote the fact that something can be done here
    And that it has been refractorised
    '''
    symbol_type, sym = match.groups()[0:2]
    return symbol_type, sym


def process_full_match(match):
    size, symbol_type, sym = match.groups()[0:3]
    size = int(size, 16)
    symbol_type = symbol_type.lower()
    if symbol_type in ['u', 'v']:
        symbol_type = 'w'
    path = match.group(4)
    return sym, symbol_type, size, path


def parse_nm(input_iterable_nm, excluded_sym=None):
    """Parse nm output.

    Argument: an iterable over lines of nm output.

    Yields: (symbol name, symbol symbol_type, symbol size, source file path).
    Path may be None if nm couldn't figure out the source file.
    """

    # Match lines with size + symbol + optional filename.
    sym_re = re.compile(r'^[0-9a-f]+ ([0-9a-f]+) (.) ([^\t]+)(?:\t(.*):\d+)?$')

    # Match lines with addr but no size.
    addr_re = re.compile(r'^[0-9a-f]+ (.) ([^\t]+)(?:\t.*)?$')
    # Match lines that don't have an address at all -- typically external symbols.
    noaddr_re = re.compile(r'^ + (.) (.*)$')

    for line in input_iterable_nm:
        line = line.rstrip()
        match = sym_re.match(line)
        if match:
            (sym, symbol_type, size, path) = process_full_match(match)
            if not (symbol_type in excluded_sym.lower()):
                yield (sym, symbol_type, size, path)
            continue
        match = addr_re.match(line)
        if match:
            process_no_size_match(match)
            continue
        match = noaddr_re.match(line)
        if match and process_no_addres_match(match):
            continue
        print >>sys.stderr, 'unparsed:', repr(line)

def demangle(ident, cppfilt):
    if cppfilt and ident.startswith('_Z'):
        # Demangle names when possible. Mangled names all start with _Z.
        ident = subprocess.check_output([cppfilt, ident]).strip()
    return ident




def parse_cpp_name(name, cppfilt):
    name = suffix_cleanup.cleanup(name, cppfilt)

    # Turn prefixes into suffixes so namespacing works.
    prefixes = [
        ['bool ',                         ''],
        ['construction vtable for ',      ' [construction vtable]'],
        ['global constructors keyed to ', ' [global constructors]'],
        ['guard variable for ',           ' [guard variable]'],
        ['int ',                          ''],
        ['non-virtual thunk to ',         ' [non-virtual thunk]'],
        ['typeinfo for ',                 ' [typeinfo]'],
        ['typeinfo name for ',            ' [typeinfo name]'],
        ['virtual thunk to ',             ' [virtual thunk]'],
        ['void ',                         ''],
        ['vtable for ',                   ' [vtable]'],
        ['VTT for ',                      ' [VTT]'],
    ]
    for prefix, replacement in prefixes:
        if name.startswith(prefix):
            name = name[len(prefix):] + replacement
    # Simplify parenthesis parsing.
    replacements = [
        ['(anonymous namespace)', '[anonymous namespace]'],
    ]
    for value, replacement in replacements:
        name = name.replace(value, replacement)

    def parse_one(val):
        """Returns (leftmost-part, remaining)."""
        if (val.startswith('operator') and not (val[8].isalnum() or val[8] == '_')):
            # Operator overload function, terminate.
            return (val, '')
        co = val.find('::')
        lt = val.find('<')
        pa = val.find('(')
        sp = val.find(' ')
        co = len(val) if co == -1 else co
        lt = len(val) if lt == -1 else lt
        pa = len(val) if pa == -1 else pa
        sp = len(val) if sp == -1 else sp
        if co < lt and co < pa or (sp < lt and sp < co and sp < pa):
            # Namespace or type name.
            return (val[:co], val[co+2:])
        if lt < pa:
            # Template. Make sure we capture nested templates too.
            open_tmpl = 1
            gt = lt
            while val[gt] != '>' or open_tmpl != 0:
                gt = gt + 1
                if len(val) <= gt:
                    return (val, '')
                if val[gt] == '<':
                    open_tmpl = open_tmpl + 1
                if val[gt] == '>':
                    open_tmpl = open_tmpl - 1
            ret = val[gt+1:]
            if ret.startswith('::'):
                ret = ret[2:]
            if ret.startswith('('):
                # Template function, terminate.
                return (val, '')
            return (val[:gt+1], ret)
        # Terminate with any function name, identifier, or unmangled name.
        return (val, '')

    parts = []
    while len(name) > 0:
        (part, name) = parse_one(name)
        assert len(part) > 0
        parts.append(part)
    return parts


def treeify_syms(symbols, strip_prefix=None, cppfilt=None):
    dirs = {}
    for sym, type, size, path in symbols:
        if path:
            path = os.path.normpath(path)
            if strip_prefix and path.startswith(strip_prefix):
                path = path[len(strip_prefix):]
            elif path.startswith('/'):
                path = path[1:]
            path = ['[path]'] + path.split('/')

        parts = parse_cpp_name(sym, cppfilt)
        if len(parts) == 1:
          if path:
            # No namespaces, group with path.
            parts = path + parts
          else:
            new_prefix = ['[ungrouped]']
            regroups = [
                ['.L.str',                 '[str]'],
                ['.L__PRETTY_FUNCTION__.', '[__PRETTY_FUNCTION__]'],
                ['.L__func__.',            '[__func__]'],
                ['.Lswitch.table',         '[switch table]'],
            ]
            for prefix, group in regroups:
                if parts[0].startswith(prefix):
                    parts[0] = parts[0][len(prefix):]
                    parts[0] = demangle(parts[0], cppfilt)
                    new_prefix += [group]
                    break
            parts = new_prefix + parts

        key = parts.pop()
        tree = dirs
        try:
            depth = 0
            for part in parts:
                depth = depth + 1
                assert part != '', path
                if part not in tree:
                    tree[part] = {'$bloat_symbols':{}}
                if type not in tree[part]['$bloat_symbols']:
                    tree[part]['$bloat_symbols'][type] = 0
                tree[part]['$bloat_symbols'][type] += 1
                tree = tree[part]
            old_size, old_symbols = tree.get(key, (0, {}))
            if type not in old_symbols:
                old_symbols[type] = 0
            old_symbols[type] += 1
            tree[key] = (old_size + size, old_symbols)
        except:
            print >>sys.stderr, 'sym `%s`\tparts `%s`\tkey `%s`' % (sym, parts, key)
            raise
    return dirs


def jsonify_tree(tree, name):
    children = []
    total = 0
    files = 0

    for key, val in tree.iteritems():
        if key == '$bloat_symbols':
            continue
        if isinstance(val, dict):
            subtree = jsonify_tree(val, key)
            total += subtree['data']['$area']
            children.append(subtree)
        else:
            (size, symbols) = val
            total += size
            assert len(symbols) == 1, symbols.values()[0] == 1
            symbol = symbol_type_to_human(symbols.keys()[0])
            children.append({
                    'name': key + ' ' + format_bytes(size),
                    'data': {
                        '$area': size,
                        '$symbol': symbol,
                    }
            })

    children.sort(key=lambda child: -child['data']['$area'])
    dominant_symbol = ''
    if '$bloat_symbols' in tree:
        dominant_symbol = symbol_type_to_human(
            max(tree['$bloat_symbols'].iteritems(),
                key=operator.itemgetter(1))[0])
    return {
        'name': name + ' ' + format_bytes(total),
        'data': {
            '$area': total,
            '$dominant_symbol': dominant_symbol,
            },
        'children': children,
        }


def dump_nm(nmfile, strip_prefix, cppfilt, excluded_sym):
    parsed_nm_list = parse_nm(nmfile, excluded_sym=excluded_sym)
    dirs = treeify_syms(parsed_nm_list, strip_prefix, cppfilt)
    return 'var kTree = ' + json.dumps(jsonify_tree(dirs, '[everything]'), indent=2)


def parse_objdump(input):
    """Parse objdump -h output."""
    sec_re = re.compile('^\d+ (\S+) +([0-9a-z]+)')
    sections = []
    debug_sections = []

    for line in input:
        line = line.strip()
        match = sec_re.match(line)
        if match:
            name, size = match.groups()
            if name.startswith('.'):
                name = name[1:]
            if name.startswith('debug_'):
                name = name[len('debug_'):]
                debug_sections.append((name, int(size, 16)))
            else:
                sections.append((name, int(size, 16)))
            continue
    return sections, debug_sections


def jsonify_sections(name, sections):
    children = []
    total = 0
    for section, size in sections:
        children.append({
                'name': section + ' ' + format_bytes(size),
                'data': { '$area': size }
                })
        total += size

    children.sort(key=lambda child: -child['data']['$area'])

    return {
        'name': name + ' ' + format_bytes(total),
        'data': { '$area': total },
        'children': children
        }


def dump_sections(objdump):
    sections, debug_sections = parse_objdump(objdump)
    sections = jsonify_sections('sections', sections)
    debug_sections = jsonify_sections('debug', debug_sections)
    size = sections['data']['$area'] + debug_sections['data']['$area']
    print 'var kTree = ' + json.dumps({
            'name': 'top ' + format_bytes(size),
            'data': { '$area': size },
            'children': [ debug_sections, sections ]})

usage = """%prog [options] MODE

Modes are:
  syms: output symbols json suitable for a treemap
  dump: print symbols sorted by size (pipe to head for best output)
  sections: output binary sections json suitable for a treemap

nm output passed to --nm-output should from running a command
like the following (note, can take a long time -- 30 minutes):
  nm -C -S -l /path/to/binary > nm.out

objdump output passed to --objdump-output should be from a command
like:
  objdump -h /path/to/binary > objdump.out"""
parser = optparse.OptionParser(usage=usage)
parser.add_option('--nm-output', action='store', dest='nmpath',
                  metavar='PATH', default='nm.out',
                  help='path to nm output [default=nm.out]')
parser.add_option('--objdump-output', action='store', dest='objdumppath',
                  metavar='PATH', default='objdump.out',
                  help='path to objdump output [default=objdump.out]')
parser.add_option('--strip-prefix', metavar='PATH', action='store',
                  help='strip PATH prefix from paths; e.g. /path/to/src/root')
parser.add_option('--filter', action='store',
                  help='include only symbols/files matching FILTER')
parser.add_option('--c++filt', action='store', metavar='PATH', dest='cppfilt',
                  default='c++filt', help="Path to c++filt, used to demangle "
                  "symbols that weren't handled by nm. Set to an invalid path "
                  "to disable.")
parser.add_option('--exclude-sym', action='store', dest='excludesymlist', type="string",
                  default="", help="list of symbols to exclude while making json"
                  "for list of symbols check your nm specification ( https://sourceware.org/binutils/docs-2.17/binutils/nm.html )"
                  "e.g. --exclude-sym=bTw")
opts, args = parser.parse_args()

if len(args) != 1:
    parser.print_usage()
    sys.exit(1)

mode = args[0]
if mode == 'syms':
    nmfile = open(opts.nmpath, 'r')
    try:
        res = subprocess.check_output([opts.cppfilt, 'main'])
        if res.strip() != 'main':
            print >>sys.stderr, ("%s failed demangling, "
                                 "output won't be demangled." % opts.cppfilt)
            opts.cppfilt = None
    except:
        print >>sys.stderr, ("Could not find c++filt at %s, "
                             "output won't be demangled." % opts.cppfilt)
        opts.cppfilt = None
    print dump_nm(nmfile, strip_prefix=opts.strip_prefix, cppfilt=opts.cppfilt, excluded_sym=opts.excludesymlist)
elif mode == 'sections':
    objdumpfile = open(opts.objdumppath, 'r')
    dump_sections(objdumpfile)
elif mode == 'dump':
    nmfile = open(opts.nmpath, 'r')
    syms = list(parse_nm(nmfile))
    # a list of (sym, type, size, path); sort by size.
    syms.sort(key=lambda x: -x[2])
    total = 0
    for sym, type, size, path in syms:
        if type in ('b', 'w'):
            continue  # skip bss and weak symbols
        if path is None:
            path = ''
        if opts.filter and not (opts.filter in sym or opts.filter in path):
            continue
        print '%6s %s (%s) %s' % (format_bytes(size), sym,
                                  symbol_type_to_human(type), path)
        total += size
    print '%6s %s' % (format_bytes(total), 'total'),
else:
    print 'unknown mode'
    parser.print_usage()

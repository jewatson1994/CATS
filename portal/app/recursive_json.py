"""Recursive JSON containers that notify SQLAlchemy for nested edits."""
from copy import deepcopy
import weakref
from sqlalchemy.ext.mutable import MutableDict


def _wrap(value, root):
    if isinstance(value, dict):
        return JSONDict(value, _root=root)
    if isinstance(value, list):
        return JSONList(value, root)
    return value


def _detach(value):
    if isinstance(value, (JSONDict, JSONList)):
        value._root = None
        for child in value.values() if isinstance(value, dict) else value:
            _detach(child)


class JSONDict(MutableDict):
    def __init__(self, value=(), *, _root=None):
        dict.__init__(self)
        self._root = weakref.ref(self) if _root is None else _root
        for key, child in dict(value).items():
            dict.__setitem__(self, key, _wrap(child, self._root))

    @classmethod
    def coerce(cls, key, value):
        if isinstance(value, cls):
            return value
        if isinstance(value, dict):
            return cls(value)
        return super().coerce(key, value)

    def changed(self):
        root = self._root() if self._root is not None else None
        if root is not None:
            MutableDict.changed(root)

    def __setitem__(self, key, value):
        # Clone before detaching: assigning an existing subtree remains valid.
        value = _wrap(value, self._root)
        if key in self:
            _detach(dict.__getitem__(self, key))
        dict.__setitem__(self, key, value)
        self.changed()

    def __delitem__(self, key):
        old = dict.__getitem__(self, key)
        dict.__delitem__(self, key)
        _detach(old)
        self.changed()

    def update(self, *args, **kwargs):
        for key, value in dict(*args, **kwargs).items():
            self[key] = value

    def setdefault(self, key, default=None):
        if key not in self:
            self[key] = default
        return self[key]

    def pop(self, key, *default):
        if len(default) > 1:
            raise TypeError("pop expected at most 2 arguments")
        if key not in self:
            if default:
                return default[0]
            raise KeyError(key)
        result = self[key]
        del self[key]
        return result

    def popitem(self):
        if not self:
            raise KeyError("popitem(): dictionary is empty")
        key = next(reversed(self))
        return key, self.pop(key)

    def clear(self):
        for value in self.values():
            _detach(value)
        dict.clear(self)
        self.changed()

    def __ior__(self, value):
        self.update(value)
        return self

    def __deepcopy__(self, memo):
        return deepcopy(dict(self), memo)

    def __reduce_ex__(self, protocol):
        return JSONDict, (dict(self),)


class JSONList(list):
    def __init__(self, value, root):
        self._root = root
        list.__init__(self, (_wrap(child, root) for child in value))

    def changed(self):
        root = self._root() if self._root is not None else None
        if root is not None:
            MutableDict.changed(root)

    def __setitem__(self, key, value):
        replacement = [_wrap(item, self._root) for item in value] if isinstance(key, slice) else _wrap(value, self._root)
        old = self[key]
        list.__setitem__(self, key, replacement)
        for child in old if isinstance(key, slice) else [old]:
            _detach(child)
        self.changed()

    def __delitem__(self, key):
        old = self[key]
        list.__delitem__(self, key)
        for child in old if isinstance(key, slice) else [old]:
            _detach(child)
        self.changed()

    def append(self, value):
        list.append(self, _wrap(value, self._root))
        self.changed()

    def extend(self, values):
        list.extend(self, [_wrap(value, self._root) for value in values])
        self.changed()

    def insert(self, index, value):
        list.insert(self, index, _wrap(value, self._root))
        self.changed()

    def pop(self, index=-1):
        value = self[index]
        del self[index]
        return value

    def remove(self, value):
        del self[self.index(value)]

    def clear(self):
        del self[:]

    def reverse(self):
        list.reverse(self)
        self.changed()

    def sort(self, *args, **kwargs):
        list.sort(self, *args, **kwargs)
        self.changed()

    def __iadd__(self, values):
        self.extend(values)
        return self

    def __imul__(self, count):
        self[:] = list(self) * count
        return self

    def __deepcopy__(self, memo):
        return deepcopy(list(self), memo)

    def __reduce_ex__(self, protocol):
        return list, (list(self),)

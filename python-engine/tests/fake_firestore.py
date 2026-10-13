"""A small in-memory stand-in for the Firestore client, enough for the engine's own calls."""

import itertools

SERVER_TS = "<server timestamp>"


class FakeSnapshot:
    def __init__(self, ref, data):
        self.reference = ref
        self.id = ref.id
        self._data = data
        self.exists = data is not None
        self.create_time = None

    def to_dict(self):
        return None if self._data is None else dict(self._data)


class FakeDocument:
    def __init__(self, collection, doc_id):
        self._collection = collection
        self.id = doc_id

    def set(self, data):
        if self._collection.db.fail:
            raise RuntimeError("network down")
        self._collection.docs[self.id] = dict(data)

    def update(self, data):
        if self._collection.db.fail:
            raise RuntimeError("network down")
        if self.id not in self._collection.docs:
            raise KeyError(f"no document {self.id}")
        self._collection.docs[self.id].update(data)

    def get(self):
        return FakeSnapshot(self, self._collection.docs.get(self.id))


class FakeQuery:
    def __init__(self, collection, conditions):
        self._collection = collection
        self._conditions = conditions

    def where(self, field=None, op=None, value=None, filter=None):
        if filter is not None:
            field, op, value = filter
        assert op == "=="
        return FakeQuery(self._collection, self._conditions + [(field, value)])

    def stream(self):
        for doc_id, data in list(self._collection.docs.items()):
            if all(data.get(f) == v for f, v in self._conditions):
                yield FakeSnapshot(FakeDocument(self._collection, doc_id), data)

    def on_snapshot(self, callback):
        self._collection.db.listeners.append((self, callback))
        return FakeWatch()


class FakeWatch:
    unsubscribed = False

    def unsubscribe(self):
        self.unsubscribed = True


class FakeCollection(FakeQuery):
    def __init__(self, db, name):
        super().__init__(self, [])
        self.db = db
        self.name = name
        self.docs = {}

    def document(self, doc_id=None):
        return FakeDocument(self, doc_id or f"{self.name}-{next(self.db.ids)}")


class FakeChange:
    class type:
        name = "ADDED"

    def __init__(self, snapshot):
        self.document = snapshot


class FakeFirestore:
    def __init__(self):
        self._collections = {}
        self.ids = itertools.count(1)
        self.listeners = []
        self.fail = False

    def collection(self, name):
        return self._collections.setdefault(name, FakeCollection(self, name))

    def docs(self, name) -> dict:
        return self.collection(name).docs

    def add(self, name, data, doc_id=None) -> str:
        """Put a document in place, as the dashboard or the console would."""
        ref = self.collection(name).document(doc_id)
        self.collection(name).docs[ref.id] = dict(data)
        return ref.id

    def fire_added(self, name, doc_id) -> None:
        """Deliver an ADDED change for one document to every listener on that collection."""
        col = self.collection(name)
        snapshot = FakeSnapshot(FakeDocument(col, doc_id), col.docs[doc_id])
        for query, callback in self.listeners:
            if query._collection is col:
                callback([snapshot], [FakeChange(snapshot)], None)

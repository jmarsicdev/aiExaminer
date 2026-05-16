from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.db.models import Base, Case, Evidence, Artifact, Bookmark


class DatabaseManager:
    def __init__(self, db_path: str = 'case.db'):
        self.engine = create_engine(f'sqlite:///{db_path}')
        Base.metadata.create_all(self.engine)   # creates new tables; skips existing ones
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)

    # ---------------------------------------------------------------- #
    #  Cases                                                             #
    # ---------------------------------------------------------------- #

    def create_case(self, case_number: str, examiner: str, description: str = '') -> int:
        with self._session() as s:
            c = Case(case_number=case_number, examiner=examiner, description=description)
            s.add(c)
            s.flush()
            return c.id

    def get_all_cases(self) -> list:
        with self._session() as s:
            return s.query(Case).all()

    def get_case_by_id(self, case_id: int):
        with self._session() as s:
            return s.query(Case).filter(Case.id == case_id).first()

    # ---------------------------------------------------------------- #
    #  Evidence                                                          #
    # ---------------------------------------------------------------- #

    def add_evidence(self, case_id: int, image_path: str) -> int:
        with self._session() as s:
            e = Evidence(case_id=case_id, image_path=image_path)
            s.add(e)
            s.flush()
            return e.id

    def get_evidence_for_case(self, case_id: int) -> list:
        with self._session() as s:
            return s.query(Evidence).filter(Evidence.case_id == case_id).all()

    # ---------------------------------------------------------------- #
    #  Artifacts                                                         #
    # ---------------------------------------------------------------- #

    def add_artifact(self, evidence_id: int, file_path: str,
                     md5: str, sha256: str, analysis_type: str, results: str) -> int:
        with self._session() as s:
            a = Artifact(
                evidence_id=evidence_id, file_path=file_path,
                md5=md5, sha256=sha256, analysis_type=analysis_type, results=results
            )
            s.add(a)
            s.flush()
            return a.id

    def get_artifacts_for_evidence(self, evidence_id: int) -> list:
        with self._session() as s:
            return s.query(Artifact).filter(Artifact.evidence_id == evidence_id).all()

    def get_artifacts_for_case(self, case_id: int) -> list:
        with self._session() as s:
            return (
                s.query(Artifact)
                 .join(Evidence)
                 .filter(Evidence.case_id == case_id)
                 .all()
            )

    # ---------------------------------------------------------------- #
    #  Bookmarks                                                         #
    # ---------------------------------------------------------------- #

    def add_bookmark(self, evidence_id: int, file_path: str,
                     tag_name: str = '', tag_color: str = '#FFDD00',
                     notes: str = '') -> int:
        with self._session() as s:
            b = Bookmark(evidence_id=evidence_id, file_path=file_path,
                         tag_name=tag_name, tag_color=tag_color, notes=notes)
            s.add(b)
            s.flush()
            return b.id

    def get_bookmarks(self, evidence_id: int) -> list:
        with self._session() as s:
            return (
                s.query(Bookmark)
                 .filter(Bookmark.evidence_id == evidence_id)
                 .order_by(Bookmark.created_at)
                 .all()
            )

    def get_bookmark(self, bookmark_id: int):
        with self._session() as s:
            return s.query(Bookmark).filter(Bookmark.id == bookmark_id).first()

    def get_bookmark_for_file(self, evidence_id: int, file_path: str):
        """Return the most recent Bookmark for a specific file, or None."""
        with self._session() as s:
            return (
                s.query(Bookmark)
                 .filter(Bookmark.evidence_id == evidence_id,
                         Bookmark.file_path == file_path)
                 .order_by(Bookmark.created_at.desc())
                 .first()
            )

    def delete_bookmark_for_file(self, evidence_id: int, file_path: str) -> None:
        """Remove all bookmark tags for a specific file."""
        with self._session() as s:
            s.query(Bookmark).filter(
                Bookmark.evidence_id == evidence_id,
                Bookmark.file_path == file_path,
            ).delete()

    def update_bookmark(self, bookmark_id: int, tag_name: str,
                        tag_color: str, notes: str) -> None:
        with self._session() as s:
            b = s.query(Bookmark).filter(Bookmark.id == bookmark_id).first()
            if b:
                b.tag_name  = tag_name
                b.tag_color = tag_color
                b.notes     = notes

    def delete_bookmark(self, bookmark_id: int) -> None:
        with self._session() as s:
            b = s.query(Bookmark).filter(Bookmark.id == bookmark_id).first()
            if b:
                s.delete(b)

    # ---------------------------------------------------------------- #
    #  Internal                                                          #
    # ---------------------------------------------------------------- #

    def _session(self):
        return _SessionCtx(self.Session)


class _SessionCtx:
    def __init__(self, Session):
        self._Session = Session
        self._s = None

    def __enter__(self):
        self._s = self._Session()
        return self._s

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self._s.rollback()
        else:
            self._s.commit()
        self._s.expunge_all()
        self._s.close()
        return False

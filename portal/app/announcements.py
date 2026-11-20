"""One current announcement per portal. A newer notice supersedes older notices."""
from datetime import datetime, timezone
from typing_extensions import TypedDict

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Mapped, Session, mapped_column

from .database import Base
from .models import utcnow


class PortalAnnouncement(Base):
    __tablename__ = "portal_announcements"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(120))
    message: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    withdrawn: Mapped[bool] = mapped_column(Boolean, default=False)


class Notice(TypedDict):
    id: int
    title: str
    message: str
    expires_at: str | None
    unread: bool


class AnnouncementRead(Base):
    __tablename__ = "portal_announcement_reads"

    announcement_id: Mapped[int] = mapped_column(ForeignKey("portal_announcements.id", ondelete="CASCADE"), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)


def mark_read(db: Session, notice_id: int, user_id: int):
    insert = pg_insert if db.get_bind().dialect.name == "postgresql" else sqlite_insert
    db.execute(insert(AnnouncementRead).values(announcement_id=notice_id, user_id=user_id)
               .on_conflict_do_nothing(index_elements=["announcement_id", "user_id"]))


def current(db: Session, user_id: int) -> Notice | None:
    read = select(AnnouncementRead.user_id).where(
        AnnouncementRead.announcement_id == PortalAnnouncement.id, AnnouncementRead.user_id == user_id).exists()
    result = db.execute(select(PortalAnnouncement, read).order_by(PortalAnnouncement.id.desc()).limit(1)).first()
    if result is None:
        return None
    row, is_read = result
    if row.withdrawn:
        return None
    expiry = row.expires_at
    if expiry is not None:
        # SQLite strips timezone information. Writes are normalized to UTC.
        expiry = expiry.replace(tzinfo=timezone.utc) if expiry.tzinfo is None else expiry.astimezone(timezone.utc)
        if expiry <= utcnow():
            return None
    return {"id": row.id, "title": row.title, "message": row.message,
            "expires_at": expiry.isoformat() if expiry else None, "unread": not is_read}

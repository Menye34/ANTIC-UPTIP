"""Internal maintenance entry point. State is operator-attested and never probed."""
import argparse

from sqlalchemy import Text, cast, select
from sqlalchemy.dialects.postgresql import insert

from .baseline_catalog import PROFILES, TOOL_STATES
from .baseline_resolution import reconcile
from .database import session_factory
from .models import Assessment, BaselineToolState


def record_tool_state(db, tool, state, capabilities):
    capabilities = sorted(set(capabilities))
    allowed = {profile.capability for profile in PROFILES if profile.tool == tool}
    if not allowed or state not in TOOL_STATES or not set(capabilities) <= allowed:
        raise ValueError('Unsupported tool state or capability.')
    table = BaselineToolState.__table__
    statement = insert(table).values(tool=tool, state=state, capabilities=capabilities, revision=1)
    # Compare canonical JSON as text because PostgreSQL JSON has no equality operator.
    db.execute(statement.on_conflict_do_update(
        index_elements=[table.c.tool],
        set_={'state': state, 'capabilities': capabilities, 'revision': table.c.revision + 1},
        where=(table.c.state != state) | (cast(table.c.capabilities, Text) != cast(statement.excluded.capabilities, Text)),
    ))


def reconcile_all(factory, trigger):
    with factory() as db:
        ids = db.scalars(select(Assessment.id).order_by(Assessment.id)).all()
    for assessment_id in ids:
        with factory.begin() as db:
            assessment = db.scalar(select(Assessment).where(Assessment.id == assessment_id).with_for_update())
            if assessment is not None:
                reconcile(db, assessment, trigger)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('reconcile', help='Reconcile existing targets or a deployed catalog change')
    tool = commands.add_parser('tool-state', help='Record trusted operator-attested tool state and reconcile')
    tool.add_argument('tool', choices=sorted({profile.tool for profile in PROFILES}))
    tool.add_argument('state', choices=TOOL_STATES)
    tool.add_argument('--capability', action='append', default=[])
    args = parser.parse_args()
    factory = session_factory()
    if args.command == 'tool-state':
        with factory.begin() as db:
            record_tool_state(db, args.tool, args.state, args.capability)
    reconcile_all(factory, 'tool_state_changed' if args.command == 'tool-state' else 'system_reconcile')


if __name__ == '__main__':
    main()

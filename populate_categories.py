from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
dbSession = DBSession()


def populate_database():
    categories = {
        "Soccer",
        "Basketball",
        "Tennis",
        "Snooker",
        "Swimming",
        "Racing",
        "Baseball",
        "Golf",
        "Skydiving",
    }

    for category in categories:
        new_category = Category(name=category)
        dbSession.add(new_category)
    dbSession.commit()


if __name__ == '__main__':
    populate_database()

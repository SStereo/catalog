from model import Base, Category, Item, User

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker



#engine = create_engine('postgresql://vagrant:vagrant@127.0.0.1:5432/np')
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

num_rows_deleted = session.query(Item).delete()
session.commit()

num_rows_deleted = session.query(Category).delete()
session.commit()



obj_categories = [
    Category(name="Soccer",
             image="http://questkermodes.com/"
             "general/2017-18/soccer_generic.jpg"),
                  Category(name="Basketball"),
                  Category(name="Baseball"),
                  Category(name="Frisbee"),
                  Category(name="Snowboarding"),
                  Category(name="Rock Climbing"),
                  Category(name="Foosball"),
                  Category(name="Skating"),
                  Category(name="Hockey")
]

obj_items = [
    Item(name="ball",
         category=obj_categories[0],
         price=129,
         description="An excellent leather ball crafted by the superior \
         company adidas in order to score in every game.",
         image="https://images-eu.ssl-images-amazon.com/images/I/91pmr1GielL._SL1500_.jpg"),
    Item(name="cap",category=obj_categories[1],
         description="Does not matter how hot the sun in shining, \
         with this cap you allways have a clear sight."),
    Item(name="tools",
         category=obj_categories[4],
         description="All tools that you need to wax and \
         to clean your snowboard."),
    Item(name="bag", category=obj_categories[6]),
    Item(name="magazine", category=obj_categories[3]),
    Item(name="bells", category=obj_categories[2]),
    Item(name="towel", category=obj_categories[1]),
    Item(name="sword", category=obj_categories[1]),
    Item(name="ring", category=obj_categories[0]),
    Item(name="book", category=obj_categories[8]),
    Item(name="DVD", category=obj_categories[2]),
    Item(name="pump", category=obj_categories[3]),
    Item(name="knife", category=obj_categories[3]),
    Item(name="cream", category=obj_categories[3]),
]

session.add_all(obj_categories)
session.commit()

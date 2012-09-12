/*
 * vncproxy
 *
 * (c) 2011 Flexiant Limited
 *
 */

#ifndef _GAUCTEST_LIST_H
#define _GAUCTEST_LIST_H

#define DECLARE_LIST2(ITEMTYPE, LISTNAME)		\
  							\
  typedef struct ITEMTYPE ## _ ## LISTNAME				\
  {									\
    ITEMTYPE * listhead;						\
    ITEMTYPE * listtail;						\
    int numitems;							\
  } ITEMTYPE ## _ ## LISTNAME ## _t;					\
  									\
  int ITEMTYPE ## _ ## LISTNAME ## _getitems(struct ITEMTYPE ## _ ## LISTNAME * l); \
  ITEMTYPE * ITEMTYPE ## _ ## LISTNAME ## _gethead(struct ITEMTYPE ## _ ## LISTNAME * l); \
  ITEMTYPE * ITEMTYPE ## _ ## LISTNAME ## _gettail(struct ITEMTYPE ## _ ## LISTNAME * l); \
  void ITEMTYPE ## _ ## LISTNAME ## _unlink(struct ITEMTYPE ## _ ## LISTNAME * l, ITEMTYPE * p); \
  void ITEMTYPE ## _ ## LISTNAME ## _addtail(struct ITEMTYPE ## _ ## LISTNAME * l, ITEMTYPE * p); \
  void ITEMTYPE ## _ ## LISTNAME ## _addhead(struct ITEMTYPE ## _ ## LISTNAME * l, ITEMTYPE * p); \
  void ITEMTYPE ## _ ## LISTNAME ## _addbefore(struct ITEMTYPE ## _ ## LISTNAME * l, ITEMTYPE * c, ITEMTYPE * p); \
  void ITEMTYPE ## _ ## LISTNAME ## _addafter(struct ITEMTYPE ## _ ## LISTNAME * l, ITEMTYPE * c, ITEMTYPE * p)
/* NOTE ABSENCE OF FINAL SEMICOLON */

#define DECLARE_LIST(ITEMTYPE) DECLARE_LIST2(ITEMTYPE, list)
#define DECLARE_SECONDARY_LIST(ITEMTYPE, PREFIX) DECLARE_LIST2(ITEMTYPE, PREFIX ## list)

#define DEFINE_LIST2(ITEMTYPE, LISTNAME, NEXTNAME, PREVNAME)	\
  									\
  int ITEMTYPE ## _ ## LISTNAME ## _getitems(struct ITEMTYPE ## _ ## LISTNAME * l) \
  {									\
    return l?l->numitems:0;						\
  }									\
  									\
  ITEMTYPE * ITEMTYPE ## _ ## LISTNAME ## _gethead(struct ITEMTYPE ## _ ## LISTNAME * l) \
  {									\
    return l?l->listhead:NULL;						\
  }									\
  									\
  ITEMTYPE * ITEMTYPE ## _ ## LISTNAME ## _gettail(struct ITEMTYPE ## _ ## LISTNAME * l) \
  {									\
    return l?l->listtail:NULL;						\
  }									\
  									\
  void ITEMTYPE ## _ ## LISTNAME ## _unlink(struct ITEMTYPE ## _ ## LISTNAME * l, ITEMTYPE * p) \
  {									\
    if (p && l)								\
      {									\
	ITEMTYPE * PREVNAME = p->PREVNAME;				\
	ITEMTYPE * NEXTNAME = p->NEXTNAME;				\
									\
	/* Fix link to PREVNAMEious */					\
	if (PREVNAME)							\
	  {								\
	    PREVNAME->NEXTNAME = NEXTNAME;				\
	  }								\
	else								\
	  {								\
	    l->listhead = NEXTNAME;					\
	  }								\
									\
	if (NEXTNAME)							\
	  {								\
	    NEXTNAME->PREVNAME = PREVNAME;				\
	  }								\
	else								\
	  {								\
	    l->listtail = PREVNAME;					\
	  }								\
									\
	p->PREVNAME = NULL;						\
	p->NEXTNAME = NULL;						\
	l->numitems--;							\
      }									\
  }									\
  									\
  /* Add a new list item to the tail */					\
  void ITEMTYPE ## _ ## LISTNAME ## _addtail(struct ITEMTYPE ## _ ## LISTNAME * l, ITEMTYPE * p) \
  {									\
    if (!p || !l)							\
      return;								\
    if (l->listtail)							\
      {									\
	if (l->listtail->NEXTNAME)					\
	  {								\
	    dolog(LOG_ERR,"ERROR: " #ITEMTYPE "_ ## LISTNAME ## _addtail found list tail has a NEXTNAME pointer"); \
	  }								\
	l->listtail->NEXTNAME = p;					\
	p->NEXTNAME = NULL;						\
	p->PREVNAME = l->listtail;					\
	l->listtail = p;						\
      }									\
    else								\
      {									\
	if (l->listhead)						\
	  {								\
	    dolog(LOG_ERR,"ERROR: " #ITEMTYPE "_ ## LISTNAME ## _addtail found no list tail but a list head"); \
	  }								\
	l->listhead = p;						\
	l->listtail = p;						\
	p->PREVNAME = NULL;						\
	p->NEXTNAME = NULL;						\
      }									\
    									\
    l->numitems++;							\
  }									\
  									\
  /* Add a new list item to the head */					\
  void ITEMTYPE ## _ ## LISTNAME ## _addhead(struct ITEMTYPE ## _ ## LISTNAME * l, ITEMTYPE * p) \
  {									\
    if (!p || !l)							\
      return;								\
    if (l->listhead)							\
      {									\
	if (l->listhead->PREVNAME)					\
	  {								\
	    dolog(LOG_ERR,"ERROR: " #ITEMTYPE "_ ## LISTNAME ## _addhead found list head has a PREVNAME pointer"); \
	  }								\
	l->listhead->PREVNAME = p;					\
	p->PREVNAME = NULL;						\
	p->NEXTNAME = l->listhead;					\
	l->listhead = p;						\
      }									\
    else								\
      {									\
	if (l->listtail)						\
	  {								\
	    dolog(LOG_ERR,"ERROR: " #ITEMTYPE "_ ## LISTNAME ## _addhead found no list head but a list tail"); \
	  }								\
	l->listtail = p;						\
	l->listhead = p;						\
	p->NEXTNAME = NULL;						\
	p->PREVNAME = NULL;						\
      }									\
									\
    l->numitems++;							\
  }									\
									\
  /* Add a new list p before current item c */				\
  void ITEMTYPE ## _ ## LISTNAME ## _addbefore(struct ITEMTYPE ## _ ## LISTNAME * l, \
				   ITEMTYPE *c,				\
				   ITEMTYPE * p)			\
  {									\
    if (!p || !l )							\
      return;								\
    if (!c)								\
      {									\
	ITEMTYPE ## _ ## LISTNAME ## _addtail(l, p);			\
	return;								\
      }									\
    if (!(c->PREVNAME))							\
      {									\
	ITEMTYPE ## _ ## LISTNAME ## _addhead(l, p);			\
	return;								\
      }									\
    									\
    /* We know c points to an item which is not the list head */	\
    p->PREVNAME = c->PREVNAME;						\
    c->PREVNAME->NEXTNAME = p;						\
    p->NEXTNAME = c;							\
    c->PREVNAME = p;							\
    									\
    l->numitems++;							\
  }									\
									\
  /* Add a new list p after current item c */				\
  void ITEMTYPE ## _ ## LISTNAME ## _addafter(struct ITEMTYPE ## _ ## LISTNAME * l, \
				  ITEMTYPE *c,				\
				  ITEMTYPE * p)				\
  {									\
    if (!p || !l )							\
      return;								\
    if (!c)								\
      {									\
	ITEMTYPE ## _ ## LISTNAME ## _addhead(l, p);			\
	return;								\
      }									\
    if (!(c->NEXTNAME))							\
      {									\
	ITEMTYPE ## _ ## LISTNAME ## _addtail(l, p);			\
	return;								\
      }									\
    									\
    /* We know c points to an item which is not the list tail */	\
    p->NEXTNAME = c->NEXTNAME;						\
    c->NEXTNAME->PREVNAME = p;						\
    p->PREVNAME = c;							\
    c->NEXTNAME = p;							\
									\
    l->numitems++;							\
  }									\

#define DEFINE_LIST(ITEMTYPE) DEFINE_LIST2(ITEMTYPE, list, next, prev)
#define DEFINE_SECONDARY_LIST(ITEMTYPE, PREFIX) DEFINE_LIST2(ITEMTYPE, PREFIX ## list, PREFIX ## next, PREFIX ## prev)

#endif /* #ifndef _GAUCTEST_LIST_H */

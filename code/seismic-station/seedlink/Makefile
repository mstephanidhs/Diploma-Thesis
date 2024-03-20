
DIRS = pcre mxml libmseed src

# Test for Makefile/makefile and run make, run configure if it exists
# and no Makefile does.

# As a special case for pcre do not pass targets except "clean".

# It will iterate over each of the directories listed in DIRS, which 
# are "pcre," "mxml," "libmseed," and "src."

# 1. checks whether a makefile exists in that directory, if not it proceeds with the configuration step
# 2. Depending on the directory ($$d) and the build target ($@), it runs the appropriate configuration 
# command. There are special configurations for the "pcre" and "mxml" directories, and a default 
# configuration for all other directories.
# 3. After configuring the project, it proceeds to build it using '$(MAKE)'
# 4. For the "pcre" directory, it runs make without any target specified when the target is not "clean." 
# This suggests that it's building "pcre" with the default target. For all other directories, it runs 
# make $@, which allows specifying a target (e.g., make clean, make install, etc.).

all clean install ::
	@for d in $(DIRS) ; do \
	  if [ ! -f $$d/Makefile -a ! -f $$d/makefile ] ; then \
	    if [ -x $$d/configure -a "$$d" = "pcre" ] ; then \
	      echo "Running configure in $$d" ; \
              ( cd $$d && touch -c * ) ; \
	      ( cd $$d && ./configure --with-link-size=4 --disable-shared --enable-static --disable-cpp ) ; \
	    elif [ -x $$d/configure -a "$$d" = "mxml" ] ; then \
	       echo "Running configure in $$d" ; \
	      ( cd $$d && ./configure --disable-shared --enable-threads ) ; \
	    else \
	      echo "Running configure in $$d" ; \
	      ( cd $$d && ./configure ) ; \
	    fi ; \
	  fi ; \
	  echo "Running $(MAKE) $@ in $$d" ; \
	  if [ -f $$d/Makefile -o -f $$d/makefile ] ; then \
	    if [ "$$d" = "pcre" -a "$@" != "clean" ] ; then \
	      ( cd $$d && $(MAKE) ) ; \
	    else \
	      ( cd $$d && $(MAKE) $@ ) ; \
	    fi ; \
	  elif [ -d $$d ] ; \
	    then ( echo "ERROR: no Makefile/makefile in $$d for $(CC)" ) ; \
	  fi ; \
	done
	

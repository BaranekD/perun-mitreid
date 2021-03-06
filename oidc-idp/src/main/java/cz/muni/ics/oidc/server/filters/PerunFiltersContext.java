package cz.muni.ics.oidc.server.filters;

import cz.muni.ics.oidc.BeanUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;

/**
 * Class that contains all custom Perun request filters. Filters are stored in the LinkedList
 * and executed in the order they are added to the list.
 *
 * Filters are configured from configuration file in following way:
 * filter.names=filterName1,filterName2,...
 *
 * @see cz.muni.ics.oidc.server.filters.PerunRequestFilter for configuration of filter
 *
 * @author Dominik Frantisek Bucik <bucik@ics.muni.cz>
 */
public class PerunFiltersContext {

	private static final Logger log = LoggerFactory.getLogger(PerunFiltersContext.class);

	private static final String FILTER_NAMES = "filter.names";
	private static final String FILTER_CLASS = ".class";
	private static final String PREFIX = "filter.";

	private List<PerunRequestFilter> filters;
	private Properties properties;
	private BeanUtil beanUtil;

	public PerunFiltersContext(Properties properties, BeanUtil beanUtil) {
		this.properties = properties;
		this.beanUtil = beanUtil;
		this.filters = new LinkedList<>();

		String filterNames = properties.getProperty(FILTER_NAMES);
		log.debug("Filter names: {}", filterNames);

		for (String filterName: filterNames.split(",")) {
			log.debug("Initializing filter: {}", filterName);
			PerunRequestFilter requestFilter = loadFilter(filterName);
			filters.add(requestFilter);
			log.info("Initialized filter: {}", filterName);
		}
	}

	public List<PerunRequestFilter> getFilters() {
		return filters;
	}

	private PerunRequestFilter loadFilter(String filterName) {
		String propPrefix = PerunFiltersContext.PREFIX + filterName;
		String filterClass = properties.getProperty(propPrefix + FILTER_CLASS, null);
		log.debug("Loading class {} for filter: {}", filterClass, filterName);
		if (filterClass == null) {
			return null;
		}
		
		try {
			Class<?> rawClazz = Class.forName(filterClass);
			if (!PerunRequestFilter.class.isAssignableFrom(rawClazz)) {
				log.error("filter class {} does not extend PerunRequestFilter", filterClass);
				return null;
			}
			
			@SuppressWarnings("unchecked") Class<PerunRequestFilter> clazz = (Class<PerunRequestFilter>) rawClazz;
			Constructor<PerunRequestFilter> constructor = clazz.getConstructor(PerunRequestFilterParams.class);
			PerunRequestFilterParams params = new PerunRequestFilterParams(filterName, propPrefix, properties, beanUtil);
			PerunRequestFilter filter = constructor.newInstance(params);
			log.info("loaded filter '{}' for {}", filter, filterName);
			return filter;
		} catch (ClassNotFoundException e) {
			log.error("filter class {} not found", filterClass);
			return null;
		} catch (NoSuchMethodException e) {
			log.error("filter class {} does not have proper constructor", filterClass);
			return null;
		} catch (IllegalAccessException | InvocationTargetException | InstantiationException e) {
			log.error("cannot instantiate " + filterClass, e);
			log.error("filter class {} cannot be instantiated", filterClass);
			return null;
		}
	}

}

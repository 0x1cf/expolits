SELECT distinct(v."CVEnum"), v.description, v.pkg_name, 
        v.distro_name, v.bug_severity, t.access_vector
FROM "v_CVE_x_bug" as v, "t_CVE_local" as t
WHERE v.distro_name = 'Android' 
	AND (v."CVEnum" ~ '2013' OR v."CVEnum" ~ '2012') 
	AND t."CVEnum" = v."CVEnum"
	AND t.access_vector ~ 'NETWORK'
	AND v.description ~ 'remote'
	AND v.pkg_name != 'chromium'
	AND v.bug_severity = 'High' ORDER by pkg_name,"CVEnum" desc;

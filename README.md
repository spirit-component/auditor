Auditor
=======


`build.conf`


```
packages = ["github.com/spirit-component/auditor"]
```
> add packages to build.conf


#### config


```
components.auditor.name-of-this-actor {

	caches {
			audit {
			driver = "go-cache"
			options = {
				expiration = 30s
				cleanup-interval = 5m
			}
		}
	}


	report {
		interval = 1s
		log-size= 10
		body-limit = 10

		filters {
			authorization {
				expr = """
				"Authorization":\".*?\"
				"""
				repl = """
				"Authorization": "*****"
				"""
			}
		}
	}

	sls {
		endpoint = "cn-beijing.log.aliyuncs.com"
        access-key-id = ""
        access-key-secret = ""

        project = gogap
        store = test 

        topic = auditor
        source = gogap
	}
}
```


### graph

```
entrypoint {
	to-audit-begin {
		seq = 1
		url = "spirit://actors/fbp/auditor/todo-auditor?action=begin"
	}

	to-todo {
		seq = 2
		url = "spirit://actors/fbp/examples-todo/todo?action=new"
	}

	to-audit-end {
		seq = 3
		url = "spirit://actors/fbp/auditor/todo-auditor?action=end&checkpoint=this-is-optional"
	}

	response {
		seq = 4
		url = "spirit://actors/fbp/postapi/external?action=callback"
	}
}
```
> limition: to-audit-begin and to-audit-end should be in same component instance

content in aliyun sls looks like:

```
__source__:  gogap
__tag__:__client_ip__:  x.x.x.x
__tag__:__receive_time__:  1543073242
__topic__:  auditor
begin_body:  {
"name"......
begin_from:  
end_body:  {"id":"55f......
end_from:  spirit://actors/fbp/examples-todo/todo?action=new
header:  {"X-Api":"todo.task.new","content-type":"application/json"}
id:  e4aecf98-c884-4ef5-8dec-45e8c382ed2f
mode:  paired
time_costs:  0.0007590000s
timestamp:  2018-11-24 15:27:22.091059 +0000 UTC
```


or 


```
entrypoint {
	
	to-audit {
		seq = 1
		url = "spirit://actors/fbp/auditor/todo-auditor?action=step&checkpoint=before-create-task"
	}

	to-todo {
		seq = 2
		url = "spirit://actors/fbp/examples-todo/todo?action=new"
	}

	response {
		seq = 3
		url = "spirit://actors/fbp/postapi/external?action=callback"
	}
}
```
> no limition, because the audit log is not ranged

content in aliyun sls looks like:

```
__source__:  gogap
__tag__:__client_ip__:  x.x.x.x
__tag__:__receive_time__:  1543073229
__topic__:  auditor
body:  {
"name":""
}
checkpoint:  error
error:  task name is empty
from:  spirit://actors/fbp/examples-todo/todo?action=new
header:  {"X-Api":"todo.task.new","content-type":"application/json"}
id:  5ce050e3-24fc-4370-936e-66e6533a1024
mode:  single
time_costs:  0.0001950000s
timestamp:  2018-11-24 15:27:08.639661 +0000 UTC
```
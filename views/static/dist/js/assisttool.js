function getLists(){
	var contentList = document.getElementById('contentList').value.toLowerCase();
	var result = document.getElementById('result');
	var htmlContent = "";
	try{
		var re = new RegExp("(.*?)\.exe", "g");
		var tasks = contentList.match(re);
		for(i=0; i<Object.keys(avList).length; i++){
			var taskid = Object.keys(avList)[i];
			for(x=0; x<tasks.length; x++){
				if(taskid.toLowerCase() == tasks[x].toLowerCase()){
					htmlContent += taskid + " <=> " + avList[taskid] + "<br>";
				}
			}
		}
	}catch(err){
		console.log(err);
	}

	for(i=0; i<Object.keys(fixedList).length; i++){
		var fixedId = fixedList[i][1];
		if(contentList.indexOf("kb") != -1 && contentList.indexOf(fixedId.toLowerCase()) == -1){
			htmlContent += "微软编号: " + fixedList[i][0] + " <=> 补丁编号: " + fixedId + " <=> 描述: " + fixedList[i][2] + " <=> 影响系统: " + fixedList[i][3] + "<br>";
		}
	}
	result.innerHTML = htmlContent;
}
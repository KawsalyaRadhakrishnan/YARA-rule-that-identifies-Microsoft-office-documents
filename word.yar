rule word_documents
{
    meta:
	   Description = "MS word documents"
	   thread_level = 1
	   in_the_wild = true
	   
	
	strings:
	   
   
    	$a = "word/document.xml" 
		$b = "docProps/app.xml"

	
 	
	condition:
	
	    $a and $b
	    
}
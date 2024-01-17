package com.devsuperior.dscatalog.projections;

/**
 * Interface criada para utilizar uma Consulta SQL nativa no UserRepository, objetivando
 * Trazer os Roles vinculados ao User, sem a necessidade de Utilizar FetchType.EAGER na 
 * annotation @ManyToMany na entidade User, já que esta abordagem para relações 'muito para muitos'
 * não é considerada uma boa prática. 
 * **/
public interface UserDetailsProjection {
	
	String getUserName();
	String getPassword();
	Long getRoleId();
	String getAuthority();
}

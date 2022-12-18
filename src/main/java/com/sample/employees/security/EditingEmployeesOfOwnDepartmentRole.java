package com.sample.employees.security;

import com.sample.employees.entity.Department;
import com.sample.employees.entity.Employee;
import com.sample.employees.entity.User;
import io.jmix.core.security.CurrentAuthentication;
import io.jmix.security.model.RowLevelBiPredicate;
import io.jmix.security.model.RowLevelPolicyAction;
import io.jmix.security.role.annotation.PredicateRowLevelPolicy;
import io.jmix.security.role.annotation.RowLevelRole;
import org.springframework.context.ApplicationContext;

@RowLevelRole(name = "Editing employees of own department", code = "editing-employees-of-own-department")
public interface EditingEmployeesOfOwnDepartmentRole {
    @PredicateRowLevelPolicy(entityClass = Department.class, actions = RowLevelPolicyAction.READ)
    default RowLevelBiPredicate<Department, ApplicationContext> departmentPredicate() {
        return (department, applicationContext) -> {
            return true;
        };
    }
    @PredicateRowLevelPolicy(entityClass = Employee.class, actions = {RowLevelPolicyAction.CREATE, RowLevelPolicyAction.UPDATE, RowLevelPolicyAction.DELETE})
    default RowLevelBiPredicate<Employee, ApplicationContext> employeePredicate() {
        return ((employee, applicationContext) -> {
            CurrentAuthentication currentAuthentication =  applicationContext.getBean(CurrentAuthentication.class);
            return employee.getDepartment().equals(((User) currentAuthentication.getUser()).getDepartment());
        });
    }

}
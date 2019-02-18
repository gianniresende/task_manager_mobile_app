import { Component } from "@angular/core";

@Component({
  selector: "tasks",
  moduleId: module.id,
  templateUrl: "tasks.component.html"

})

export class TasksComponent{
  public tasks: Array<any> = [];

  public constructor(){
    this.tasks = [
      {id: 1, title: "Comprar Notebook Novo", done: false },
      {id: 2, title: "Lavar o Carro", done: true },
      {id: 3, title: "Estudar NativeScript", done: false },
      {id: 4, title: "Cobrir casa da roça", done: false }
    ]
  }
}
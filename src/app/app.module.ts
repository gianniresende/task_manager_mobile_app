// angular imports
import { NgModule, NO_ERRORS_SCHEMA } from "@angular/core";

//nativescript imports
import { NativeScriptHttpModule } from "nativescript-angular/http";
import { NativeScriptModule } from "nativescript-angular/nativescript.module";
//import { NativeScriptHttpClientModule } from "nativescript-angular/http-client";
// import { NativeScriptFormsModule } from "nativescript-angular/forms";


//app core imports
import { AppComponent } from "./app.component";
import { AppRoutingModule } from "./app-routing.module";


//componentes imports
import { HomeComponent } from "./home/home.component";
import { SignInComponent } from "./sign-in/sign-in.component";
import { SignUpComponent } from "./sign-up/sign-up.component";


//service imports
import { AuthGuard } from "./guards/auth.guard";
import { AuthService } from "./shared/auth.service";
import { TokenService } from "./shared/token.service";


@NgModule({
    bootstrap: [
      AppComponent
    ],
    imports: [
      AppRoutingModule,
      NativeScriptHttpModule,
      NativeScriptModule        
    ],
    declarations: [
      AppComponent,
      HomeComponent,
      SignInComponent,
      SignUpComponent
    ],
    providers: [
      AuthGuard,
      AuthService,
      TokenService
    ],
    schemas: [
      NO_ERRORS_SCHEMA
    ]
})
/*
Pass your application module to the bootstrapModule function located in main.ts to start your app
*/
export class AppModule { }
